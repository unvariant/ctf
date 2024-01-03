# hashmaster

## Level 1
**Submit shellcode that produces a hash of itself and writes it to a specific memory location.**

Solve is pretty easy, `@JoshL` found a sha256 implementation online. Write a program that reads its own code in C and then convert to shellcode.

## Level 2
**Shellcode is not allowed to read itself.**
This one is slightly harder, now the shellcode is not allowed to read itself. To work around this constraint we generate a prologue that pushes hardcoded program bytes onto the stack so they can be read and hashed. Of course this sequence of pushes can't push itself, so instead they use a repetitive format that is easily reconstructed and added to the hash.

The generation code can be found in `conv.py`.

## Level 3
**instruction pointer is not allowed to move backwards**
Did not solve.

## Level 4
**instruction pointer is not allowed to move backwards, and shellcode is not allowed to read itself.**
Did not solve.