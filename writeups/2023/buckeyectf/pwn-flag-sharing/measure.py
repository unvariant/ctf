
from instancer.pow import solve_challenge
from pwn import *
from subprocess import run
from time import sleep
import matplotlib.pyplot as plt

# build stuff
run(["./build.sh", "measure"], check=True)

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

p = remote(ip, port)

flag = p8(0b01010101) * 64
# flag = p8(0b00111111) * (1 << 14)
# start_bot(flag)

sleep(5)

# ** your really great solution goes here **
p.send(b"H" + open("measure.bin", "rb").read().ljust(0x1000, b"\x00"))

print(p.recvuntil(b"starting testing...\n").decode())

try:
    while True:
        p.recvuntil(b"MSG:")
        print(p.recvline().decode().strip())
except (KeyboardInterrupt, EOFError) as e:
    pass