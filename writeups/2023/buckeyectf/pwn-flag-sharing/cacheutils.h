#ifndef CACHEUTILS_H
#define CACHEUTILS_H

#include <stdint.h>

#ifndef HIDEMINMAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif

uint64_t rdtsc_nofence() {
  uint64_t a, d;
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  return a;
}

uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

uint64_t rdtsc_begin() {
  uint64_t a, d;
  asm volatile (
    "mfence\n"
    "CPUID\n"
    "RDTSCP\n"
    "mov %0, rdx\n"
    "mov %1, rax\n"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "rax", "rbx", "rcx", "rdx");
  a = (d << 32) | a;
  return a;
}

uint64_t rdtsc_end() {
  uint64_t a, d;
  asm volatile(
    "mfence\n\t"
    "RDTSCP\n\t"
    "mov %0, rdx\n\t"
    "mov %1, rax\n\t"
    "CPUID\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "rax", "rbx", "rcx", "rdx");
  a = (d << 32) | a;
  return a;
}

void maccess(uint64_t p)
{
  asm volatile ("mov rax, qword ptr [%0]\n"
    :
    : "c" (p)
    : "rax");
}

void longnop()
{
  asm volatile ("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n");
}
#endif