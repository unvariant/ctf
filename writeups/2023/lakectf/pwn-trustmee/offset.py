#!/usr/bin/python3

from pwn import *
import sys

libc = ELF("./libc.so.6")

print(f"0x{libc.sym[sys.argv[1]]:x}")