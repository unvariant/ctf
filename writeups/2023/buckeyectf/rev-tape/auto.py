from pwn import *

context.terminal = ["kitty"]
p = gdb.debug(["./belt", "flag_checker"], api=True)
g = p.gdb
p.sendline(open("input.txt", "rb").read())

filebase = int(g.execute("pie 0", to_string=True).split("= ")[1], 16)
log.info(f"filebase: {filebase:x}")
eval_loop = filebase + 0xae8a

g.execute(f"b *0x{eval_loop:x}")
g.continue_and_wait()

buffer = int(g.execute("x/1xg $rsp", to_string=True).split(":")[1].strip(), 16)
output = open("expected.txt", "w+")

def parse(state):
    state = state.strip().split("\n")
    state = map(lambda s: s.split(":")[1], state)
    state = " ".join(state).split()
    state = list(map(lambda s: int(s.strip(), 16), state))
    return state

while True:
    state = parse(g.execute(f"x/64xb 0x{buffer:x}", to_string=True))
    pc = int(g.execute(f"x/1xg $rsp+0x38", to_string=True).split(":")[1].strip(), 16)
    buf, cap, head, length = parse(g.execute(f"x/4xg $rsp", to_string=True))
    output.write(f"{state}|{pc}|{cap}|{head}|{length}\n")
    g.continue_and_wait()

p.interactive()