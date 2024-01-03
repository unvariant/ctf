from pwn import *
from copy import deepcopy
from z3 import *

class deque:
    def __init__(self):
        self.len = 0x40
        self.data = [0xbb] * 64
        self.head = 0

    def rotate(self, n):
        cur = self[0]
        self.head += n
        return cur

    def left(self):
        return self.rotate(1)

    def right(self):
        return self.rotate(-1)

    def push(self): return self.right()

    def pop(self): return self.left()

    def __getitem__(self, n):
        return self.data[(self.head + n) % self.len]

    def __setitem__(self, n, v):
        self.data[(self.head + n) % self.len] = v

sol = Solver()

count = 0
def ascii():
    global count, sol
    i = BitVec(chr(0x41 + count), 8)
    sol.add(i >= 0x20)
    sol.add(i <= 0x7f)
    return i

output = open("output.txt", "w+")

class State:
    def __init__(self, bytecode, input):
        self.stack = deque()
        self.pc = 0
        self.bytecode = bytecode
        self.input = iter(input)

    def print(self, s):
        global output
        output.write(s)

def unimplemented(s):
    byte = s.bytecode[s.pc]
    log.error(f"unimplemented opcode {byte:x}")

def byteinput(s):
    global count, sol
    known = b"bctf{"
    s.stack.push()
    s.stack[0] = ascii()
    if count < len(known):
        sol.add(s.stack[0] == known[count])
    if count == 28:
        sol.add(s.stack[0] == ord("}"))
    count += 1
    s.pc += 1
    # return f"PUSH | {s.stack[0]:02x}"

def dup(s):
    prev = s.stack[0]
    s.stack.push()
    s.stack[0] = prev
    s.pc += 1
    # return f"DUP | {prev:02x}"

def pushbytecode(s):
    arg1 = s.bytecode[s.pc + 1]
    s.stack.push()
    s.stack[0] = arg1
    s.pc += 2
    # return f"PUSH | {arg1:02x}"

def pop(s):
    b = s.stack.pop()
    s.pc += 1
    # return f"POP | {b:02x}"

def nand(s):
    a = s.stack.pop()
    b = s.stack.pop()
    s.stack.push()
    s.stack[0] = (~(a & b)) & 0xff
    s.pc += 1
    # return f"NAND | {a:02x} | {b:02x}"

def subtract(s):
    a = s.stack.pop()
    b = s.stack.pop()
    s.stack.push()
    s.stack[0] = If(a - b < 0, 0, a - b) # max(0, a - b)
    s.pc += 1
    # return f"SUB | {a:02x} | {b:02x}"

def dump(model):
    flag = list(map(lambda e: e[1], sorted([(var, chr(model[var].as_long())) for var in model], key=lambda e: str(e[0]))))
    print("".join(flag))

def ne(s):
    amount = s.stack.pop()
    condition = s.stack.pop()
    s.pc += 1
    sol.add(condition == 0)
    print(sol.check())
    m = sol.model()
    dump(m)
    if m.eval(condition).as_long() != 0:
        s.pc += amount
    # return f"NE | {amount:02x} | {condition:02x}"

def eq(s):
    global sol
    amount = s.stack.pop()
    condition = s.stack.pop()
    s.pc += 1
    sol.add(condition == 0)
    print(sol.check())
    m = sol.model()
    dump(m)
    if m.eval(condition).as_long() == 0:
        s.pc += amount
        if amount == 0x28:
            sol.add(condition == 0)
    # return f"EQ | {amount:02x} | {condition:02x}"

def add(s):
    a = s.stack.pop()
    b = s.stack.pop()
    s.stack.push()
    s.stack[0] = If(a + b > 0xff, 0xff, a + b) # min(a + b, 0xff)
    s.pc += 1
    # return f"ADD | {a:02x} | {b:02x}"

def printhead(s):
    c = s.stack.pop()
    s.print(chr(c))
    s.pc += 1
    # return f"PRINT | {c:02x}"

instructions = {
    0x00: pushbytecode,
    0x01: pop,
    0x02: dup,
    0x10: eq,
    0x12: ne,
    0x20: add,
    0x21: subtract,
    0x22: unimplemented,
    0x23: unimplemented,
    0x24: nand,
    0x40: printhead,
    0x41: unimplemented,
    0x42: byteinput,
    0x43: unimplemented,
}

bytecode = open("flag_checker", "rb").read()
state = State(bytecode, open("input.txt", "r").readlines())
expected = open("current.txt", "r").readlines()
expected = map(lambda s: list(s.split("|")), expected)
expected = map(lambda e: [e[0], *map(int, e[1:])], expected)
expected = list(expected)

i = 0
oneshot = True
prev = None
executed = 0
while state.pc < len(state.bytecode):
    byte = state.bytecode[state.pc]
    if byte == 0x50:
        log.info(f"end: {state.pc}")
        log.info(f"EXITING")
        break

    try:
        r = instructions[byte](state)
        # stack = [f"{state.stack[i]:02x}" for i in range(0x10)]
        # log.info(f"{r.ljust(16, ' ')} | {stack}")
        executed += 1
    except:
        log.error(f"FAILED AT: pc: {state.pc}, limit: {len(state.bytecode)}")

    # if i < len(expected):
    #     ex, pc, cap, head, length = expected[i]
    #     err = \
    # f"""
    # byte: 0x{byte:x}
    # ex: {ex} | {pc} | {head}
    # me: {state.stack.data} | {state.pc} | {state.stack.head % 0x40}
    # """
    #     if not (ex == str(state.stack.data) and pc == state.pc and length == 0x40 and head == (state.stack.head % 0x40)):
    #         log.error(f"{prev}\n{err}")

    #     prev = err

    #     i += 1
    # elif oneshot:
    #     log.info(f"pc: {state.pc}, byte: 0x{byte:x}")
    #     oneshot = False

log.info(f"executed: {executed}")
log.info(f"DONE")