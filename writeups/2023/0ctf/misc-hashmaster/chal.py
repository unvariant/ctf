from pwn import *
import base64
import hashlib
from unicorn import *
from unicorn.x86_const import *

context.arch = 'amd64'

CODE=0x1000000
CODELEN=0x200000
DATA=0x2000000
DATALEN=0x1000

def hook(uc, access, address, size, value, user_data):
    assert access == UC_MEM_READ
    assert DATA <= address
    assert address + size <= DATA + DATALEN

sha = open('sha256.dat', 'rb').read()
sc = open('exp.dat','rb').read()
assert len(sc) % 64 == 0

mu = Uc(UC_ARCH_X86, UC_MODE_64)

mu.mem_map(CODE, CODELEN, UC_PROT_ALL)
mu.mem_map(DATA, DATALEN, UC_PROT_ALL)
mu.mem_write(CODE, sc)
mu.hook_add(UC_HOOK_MEM_READ, hook)

try:
    mu.emu_start(CODE, CODE+len(sc))
except Exception as e:
    print(e)
    print(f"rip: @ {mu.reg_read(UC_X86_REG_RIP):#x}")

data = sc
# data = sc[:0x80]
print(hex(len(data)))
print(mu.mem_read(DATA, 0x20).hex())
print(hashlib.sha256(data).hexdigest())
ans = base64.b64encode(sc).decode()
# print(ans)

"""
sc = base64.b64decode(input())
uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
uc_mem_map(uc, 0x1000000, 0x200000, UC_PROT_ALL);
uc_mem_map(uc, 0x2000000, 0x1000, UC_PROT_ALL);
uc_mem_write(uc, 0x1000000, sc, len(sc));

# Run unicorn
# Get first 0x20 bytes at 0x2000000
dat = uc_mem_read(uc, 0x2000000, 0x20)
assert hashlib.sha256(sc) == dat
"""