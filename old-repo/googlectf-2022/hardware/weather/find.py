# function to check if byte a contains byte b
def valid(a, b):
    return a | b == a

# 02h is the opcode for LJMP
# 12h is the opcode for LCALL
ops = [0x02, 0x12]

# firmware bytes extracted from the eeprom
# in an earlier program
f = open("firmware.bin", "rb")
d = f.read()
f.close()

ps = []
for i in range(len(d)-1):
    b = d[i]
    # stop when the FFh region is reached
    if d[i:i+3] == b'\xff\xff\xff':
        break
    for op in ops:
        h = d[i + 1]
        if valid(b, op) and valid(h, 0x0A):
            ps.append(hex(i))

print(ps)