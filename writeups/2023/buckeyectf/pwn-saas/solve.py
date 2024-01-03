from base64 import b64encode
from pwn import *

p = remote("chall.pwnoh.io", 13375)

sc = open("solve.bin", "rb").read().hex()
print(sc)
p.sendline(sc)

p.interactive()