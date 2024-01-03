#include <stdint.h>
#include <immintrin.h>

typedef uint64_t u64;
typedef int64_t  i64;

__attribute__((naked))
i64 syscall(i64 nr, ...) {
    asm volatile(
        "push r8\n"
        "push r9\n"
        "push r10\n"
        "push r11\n"
        "push rcx\n"
        "mov rax, rdi\n"
        "mov rdi, rsi\n"
        "mov rsi, rdx\n"
        "mov rdx, rcx\n"
        "mov r10, r8\n"
        "mov r8,  r9\n"
        "mov r9,  qword ptr [rsp + 48]\n"
        "syscall\n"
        "pop rcx\n"
        "pop r11\n"
        "pop r10\n"
        "pop r9\n"
        "pop r8\n"
        "ret\n"
    );
}

void exit(int code) {
    syscall(0x3c, code);
}

void putchar (char ch) {
    volatile char sch = ch;
    syscall(1, 1, &sch, 1);
}

void print (char * s) {
    while (*s != 0) {
        putchar(*s);
        s++;
    }
}

void puts (char * s) {
    print(s);
    putchar('\n');
}

char hexchar(char ch) {
    if (ch < 10) return ch + '0';
    return ch + ('A' - 10);
}

void hex(u64 n) {
    char buf[32];
    for (int i = 0; i < 16; i++) {
        buf[i] = hexchar(n >> 60);
        n <<= 4;
    }
    buf[16] = 0;
    print("0x");
    print(buf);
}

int dec(u64 n) {
    char buf[32];
    char *ptr = buf+31;
    *ptr = 0;
    do {
        *--ptr = n % 10 + '0';
        n /= 10;
    } while (n != 0);
    print(ptr);
    return buf+31-ptr;
}

void delay(u64 amount) {
    u64 start = __rdtsc();
    while (__rdtsc() - start < amount);
}