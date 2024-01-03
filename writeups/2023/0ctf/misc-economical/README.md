# economical

For this challenge you have to write shellcode that sorts an array of 100 bytes, and perform the task 10 times. The catch is that you are only allowed to use single byte instructions in x86 32 bit mode. There is also a max total executed instructions of 1,000,000 which means we cannot do O(n^2) algorithms because they use too many instructions.

`bubble.asm` contains my initial bubble sort implementation that times out because it exceeds the 1,000,000 instruction limit.

`count.asm` contains counting sort algorithm which is about O(n) and managed to solve the challenge.

## Explanation
In 32 bit mode, the useful single byte instructions are:
```x86asm
push [reg]
pop [reg]
popad
pushad
xchg eax, [reg]
inc [reg]
dec [reg]
pushfd
popfd
sahf
lahf
movsb
cmpsb
stosb
lodsb
scasb
ret
salc
xlatb
cmc
```

### Implementing `mov`
`mov [dst], [src]` can be easily implemented as:
```x86asm
push [src]
pop [dst]
```

### Implementing comparisons
The `cmp` instruction does not show up in our list of single byte instructions, so how are we supposed to sort a list of bytes? The answer lies one undocumented instruction and another very old instruction that was present in the original 8086 instruction set:

`xlatb` and `salc`.

- `xlatb` is equivalent to `mov al, byte [ebx + al]`
- `salc` sets `al` to `0xff` if the carry flag is set, and `0x00` otherwise.
- `cmpsb` is equivalent to `cmp byte [esi], byte [edi]` (if such a m8/m8 `cmp` form existed)

So in order to compare two bytes we point `esi` to the first byte, and `edi` to the second byte. `cmpsb` compares the two bytes a crucially sets the carry flag based on the result. `salc` reads the carry flag into `al` and we add one to adjust the `salc` result from `0xff` or `0x00` to `0x00` or `0x01`. Now `xlatb` can be used to grab a byte from the memory pointed to by `ebx` based on `al`.

### Implementing branching
The challenge employs a fixed memory layout so we can push the target location we want to branch to and execute a `ret` to branch to there.