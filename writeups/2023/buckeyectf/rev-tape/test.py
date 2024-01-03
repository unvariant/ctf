from pwn import *

p = process(["./belt", "flag_checker"])

bytecode = open("./flag_checker", "rb").read()

p.sendline(open("input.txt", "rb").read())

p.interactive()