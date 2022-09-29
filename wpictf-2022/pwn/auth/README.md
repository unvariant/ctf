# Auth

The problem provides two files, `auth.elf` and `install.sh`.

## checksec
```
    Arch:     aarch64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```

## file
```
auth.elf: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.31.so, for GNU/Linux 3.7.0, BuildID[sha1]=07238de315ee45d17d3f031cb844b97b2b5fe66c, not stripped
```

Could this be? Is this actually a non x86_64 pwn problem? And even better its arm (specifically aarch64 which is 64 bit arm) pwn? WPICTF I love you guys.

Anyways back to the problem. The `install.sh` gives instructions to install aarch64 binutils (for debugging) and qemu-aarch64 (for emulating aarch64 files). One small issue was that even after installing qemu, when trying to run `auth.elf` using qemu it would error with:
```
$ qemu-aarch64 auth.elf
./ld-2.31.so: No such file or directory
```
I have a m1 mac, and m1 is just what apple calls the armv8 processor. To get the necessary libc files I started an aarch64 ubuntu 20.04 container and copied the ld and libc from that container. Afterwards qemu was able to run without any errors.

This first thing I noticed when decompiling the binary with ghidra is that every function starts with `paciasp` and ends with `retaa`.

First a small introduction to how aarch64 works. aarch64 has 32 64 bit registers, `x0` through `x31`. The lower 32 bits of these registers are accessable as `x0` through `w31`. aarch64 also has a zero register, `xzr` and its lower 32 bits `wzr`. When a function is called via the `bl` (branch with link) instruction, the return address is NOT pushed onto the stack. Instead the return address is saved in the userspace accessable register `x30`, more commonly known as `lr` (link register). Register `x30` points to the current stack and is known as `sp` (stack pointer).

The way that PAC works is taking advantage of the fact that all 64 bit systems do not actually use a full 64 bit address space. Most operating systems using around 48 address bits. This is because 48 address bits allows a processor to address 256 terabytes of memory, and I sincerely doubt many people need that much memory. PAC uses this extra space in the upper address bits of 64 bit pointers to store the authentication information.

`paciasp` stands for `Pointer Authentication Code for Instruction Address Stack Pointer (using key A)`

`paciasp` signs the link register with a cryptographic key using three inputs, the value of the link register itself, the stack pointer, and a key supplied by hardware.

`retaa` stands for `Return Authenticate Address (using key A)`

`retaa` checks the cryptographic key in the link register, if it is valid then the key is removed and the unmangled value is written to the link register, and afterwards the link register is written into the program counter. Otherwise the instruction will generate a segmentation fault.