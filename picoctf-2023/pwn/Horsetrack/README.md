# Horsetrack
Points: 300

This problem is a standard heap challenge.
```
1. Add a horse
2. Remove a horse
3. Race
4. Exit
Choice: 
```
There is also one hidden menu option not displayed to the user, which allows overwriting the first 16 bytes of any chunk.
```
0. Cheat
```

The vulnerability is how the binary takes in input.
```c
void input(char *param_1,uint param_2) {
    int iVar1;
    char *local_20;
    char local_d;
    int local_c;

    printf("Enter a string of %d characters: ",(ulong)param_2);
    local_c = 0;
    local_20 = param_1;
    while( true ) {
        if ((int)param_2 <= local_c) {
            do {
                iVar1 = getchar();
            } while ((char)iVar1 != '\n');
            *local_20 = '\0';
            return;
        }
        iVar1 = getchar();
        local_d = (char)iVar1;
        while (local_d == '\n') {
            iVar1 = getchar();
            local_d = (char)iVar1;
        }
        if (local_d == -1) break;
        *local_20 = local_d;
        local_c = local_c + 1;
        local_20 = local_20 + 1;
    }
    return;
}
```
The issue is that the `input` function will bail if `getchar` ever returns `-1`. You might think that a `-1` return value
only occurs if `getchar` fails to read, but `getchar` return type of `getchar` is a signed int, not a char. This means that
if `getchar` ever reads the character `0xFF` it will be casted to `-1` and the input function will end early.

Why is this important? If the input function does not populate the allocated chunks with data, then heap pointers can be leaked
because the old data in the chunks was not overwritten.

The binary is position dependent, and contains a dynamic entry for `system`, meaning that we do not have to worry about the libc.
The binary is also using glibc 2.35, meaning that in order to overwrite points in the tcache or fastbin we need a heap leak first.
Thankfully this can be accomplished using the bug described above.

Exploit:
1. leak heap address
2. calculate heap base
3. use the hidden edit function to overwrite a tcache chunk next pointer to the `free` GOT entry
4. overwrite the `free` GOT entry to point to the `system` PLT entry
5. delete a chunk that contains `/bin/sh`, triggering a call to `system("/bin/sh")` and popping a shell