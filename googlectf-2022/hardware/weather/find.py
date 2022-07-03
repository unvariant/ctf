def valid(a, b):
    return a | b == a

ops = [0x02, 0x12]

f = open("firmware.bin", "rb")
d = f.read()
f.close()

ps = []
for i in range(len(d)-2):
    b = d[i]
    if d[i:i+3] == b'\xff\xff\xff':
        break
    for op in ops:
        h = d[i + 1]
        l = d[i + 2]
        if valid(b, op) and valid(h, 0x0A):
            ps.append(hex(i))

print(ps)