
from instancer.pow import solve_challenge
from pwn import *
from subprocess import run
from time import sleep
import matplotlib.pyplot as plt

# build stuff
run(["./build.sh", "solve"], check=True)

# fill in port number here
if args.REMOTE:
    host = "3.142.53.224"
else:
    host = "localhost"
p_gateway = remote(host, 9000)

# Solve the proof-of-work if enabled (limits abuse)
pow = p_gateway.recvline()
if pow.startswith(b"== proof-of-work: enabled =="):
    p_gateway.recvline()
    p_gateway.recvline()
    challenge = p_gateway.recvline().decode().split(" ")[-1]
    p_gateway.recvuntil(b"Solution? ")
    p_gateway.sendline(solve_challenge(challenge))

# Get the IP and port of the instance
p_gateway.recvuntil(b"ip = ")
if args.REMOTE:
    ip = p_gateway.recvuntil("\n").decode().strip()
else:
    ip = "localhost"
p_gateway.recvuntil(b"port = ")
port = int(p_gateway.recvuntil("\n").decode().strip())

# Helper to start the bot (which has the flag)
# (optionally, you can start the bot with a fake flag for debugging)
def start_bot(fake_flag=None):
    p_gateway.recvuntil(b"Choice: ")

    if fake_flag is not None:
        p_gateway.sendline(b"2")
        p_gateway.recvuntil(b":")
        p_gateway.sendline(fake_flag)
    else:
        p_gateway.sendline(b"1")

    p_gateway.recvuntil(b"Bot spawned")

def readexact(conn, n):
    data = b""
    while len(data) < n:
        data += p.recv(n-len(data), timeout=10)
    return data

p = remote(ip, port)

# ** your really great solution goes here **
p.send(b"H" + open("solve.bin", "rb").read().ljust(0x1000, b"\x00"))

print(p.recvuntil(b"starting testing...\n").decode())

flag = (p8(0b00_01_10_11)) * 512
flag = (p8(0b01_01_01_01)) * 512
start_bot(flag)

timings = [[], [], [], []]
offset = 0
window = 1 << 17
update = window >> 6
limit = 400
fig, plots = plt.subplots(4)
x_axis = list(range(window))
try:
    while True:
        data = readexact(p, 16)
        rounds = [u32(data[i:i+4]) for i in range(0, 16, 4)]
        
        [timings[i].append(rounds[i]) for i in range(4)]
        
        length = len(timings[0])

        if length % update == 0:
            if length > window:
                offset += update
            timings = list(map(lambda r: r[-window:] + [0 for _ in range(window - len(r))], timings))
            [p.clear() for p in plots.flat]
            [p.axis([0, window, 200, limit]) for p in plots]
            """
            [0] -> S
            [1] -> W
            [2] -> D
            [3] -> A
            """
            plots[0].plot(x_axis, timings[1], 'yo')
            plots[1].plot(x_axis, timings[3], 'go')
            plots[2].plot(x_axis, timings[0], 'ro')
            plots[3].plot(x_axis, timings[2], 'bo')
            plt.pause(0.001)
            plt.show(block=False)
except (KeyboardInterrupt, EOFError) as e:
    log.info(f"ERROR: {e}")

plt.show()