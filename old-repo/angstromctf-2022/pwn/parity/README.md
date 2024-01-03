# Parity
ghidra output
```
undefined8 main(void) {
    __gid_t __rgid;
    code *__buf;
    ssize_t sVar1;
    int local_c;
  
    setbuf(stdout,(char *)0x0);
    __rgid = getegid();
    setresgid(__rgid,__rgid,__rgid);
    printf("> ");
    __buf = (code *)mmap((void *)0x0,0x2000,7,0x22,0,0);
    sVar1 = read(0,__buf,0x2000);
    local_c = 0;
    while( true ) {
        if ((int)sVar1 <= local_c) {
            (*__buf)();
            return 0;
        }
        if (((byte)__buf[local_c] & 1) != (local_c - (local_c >> 0x1f) & 1U) + (local_c >> 0x1f)) break;
        local_c = local_c + 1;
    }
    puts("bad shellcode!");
    return 1;
}
```
In this binary they allocate a `0x2000` byte buffer using mmap with the memory protection bits set as `PROT_READ`, `PROT_WRITE`, and `PROT_EXEC`. This means that the `mmap`ed memory is readable, writable, and executable. The program reads user input into the buffer, asserts that the user input contains only alternating even and odd bytes starting with an even byte. If this check is passed it jumps into the buffer which causes whatever input is in the buffer to be executed as code. The attack is simple, write an assembly program consisting on only alternating even and odd bytes, invoke `execve` with `syscall`, `sysenter`, or `int 0x80`. I very likely massively overcomplicated things but the assembly program came out to be around 150 lines long, but it worked.
```
[+] Opening connection to challs.actf.co on port 31226: Done
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
actf{f3els_like_wa1king_down_4_landsl1de_6d28d72fd7db}
```
## Flag: actf{f3els_like_wa1king_down_4_landsl1de_6d28d72fd7db}