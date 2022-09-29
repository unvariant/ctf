# Ropes
## Stop doing jumpropes.
 - author: Eth007
 - solves: 18

This problem provides a binary, libc, and dynamic linker.<br>
Decompiling the binary using ghidra:
```c
undefined8 main(void) {
  long in_FS_OFFSET;
  undefined8 *local_20;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("%p\n",puts);
  fgets(inp,0x100,stdin);
  __isoc99_scanf("%ld%*c",&local_20);
  __isoc99_scanf("%ld%*c",&local_18);
  *local_20 = local_18;
  puts("ok");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
binary protections:
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```
A setup function runs before main and disallows all syscalls except read, write, open, and fstat via seccomp. This prevents using a one gadget or anything execve related to grab a shell. With the limited syscalls it should be impossible to do anything other than read and write into files.

The binary leaks the dynamic address of puts which means we can calculate the libc base address. It then reads 256 bytes into a global buffer, performs a single arbitrary write, and outputs `"ok"` before returning.

I am fairly certain that with the current leaked information and binary protections it is impossible to pop a shell using a single arbitrary write. The first goal should be to force main to call itself in order to gain infinite arbitrary writes and allow us to perform an attack
Full relro is turned on so the GOT entries cannot be overwritten using the single