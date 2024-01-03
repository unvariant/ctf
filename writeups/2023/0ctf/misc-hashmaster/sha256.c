void __attribute__((section(".entry"), naked)) _start() {
    asm volatile(
        "call exploit\n"
    );
}

//usr/bin/env clang -Ofast -Wall -Wextra -pedantic ${0} -o ${0%%.c*} $* ;exit $?
//
//  SHA-256 implementation, Mark 2
//
//  Copyright (c) 2010,2014 Literatecode, http://www.literatecode.com
//  Copyright (c) 2022 Ilia Levin (ilia@levin.sg)
//
//  Permission to use, copy, modify, and distribute this software for any
//  purpose with or without fee is hereby granted, provided that the above
//  copyright notice and this permission notice appear in all copies.
//
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

#include <stdint.h>
#include <stddef.h>
#include <immintrin.h>
#define SHA256_SIZE_BYTES    (32)

#define SHA256_SIZE_BYTES    (32)

typedef struct {
    uint8_t  buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[64];
} __attribute__((aligned(32))) sha256_context;

#ifndef _cbmc_
#define __CPROVER_assume(...) do {} while(0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FN_ static inline __attribute__((const, always_inline))
#define CODEADDR 0x1000000
#define CODELEN 0x13371337
#define DATAADDR 0x2000000
#define DATALEN 0x1000

// -----------------------------------------------------------------------------
FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
    return ((x >> (n & 31)) & 0xff);
} // _shb


// -----------------------------------------------------------------------------
FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
    return ((x << (n & 31)) & 0xffffffff);
} // _shw


// -----------------------------------------------------------------------------
FN_ uint32_t _r(uint32_t x, uint8_t n)
{
    return ((x >> n) | _shw(x, 32 - n));
} // _r


// -----------------------------------------------------------------------------
FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ ((~x) & z));
} // _Ch


// -----------------------------------------------------------------------------
FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (x & z) ^ (y & z));
} // _Ma


// -----------------------------------------------------------------------------
FN_ uint32_t _S0(uint32_t x)
{
    return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
} // _S0


// -----------------------------------------------------------------------------
FN_ uint32_t _S1(uint32_t x)
{
    return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
} // _S1


// -----------------------------------------------------------------------------
FN_ uint32_t _G0(uint32_t x)
{
    return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
} // _G0


// -----------------------------------------------------------------------------
FN_ uint32_t _G1(uint32_t x)
{
    return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
} // _G1


// -----------------------------------------------------------------------------
FN_ uint32_t _word(uint8_t *c)
{
    return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
} // _word


// -----------------------------------------------------------------------------
FN_ void _addbits(sha256_context *ctx, uint32_t n)
{
    // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

    if (ctx->bits[0] > (0xffffffff - n)) {
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    }
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} // _addbits

#define FUCK(i) K[i] = (((uint32_t[64]){ \
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, \
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, \
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, \
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, \
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, \
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, \
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, \
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, \
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, \
    })[i])

// -----------------------------------------------------------------------------
FN_ void _hash(sha256_context *ctx)
{
    uint32_t K[64];
    FUCK(0);FUCK(1);FUCK(2);FUCK(3);FUCK(4);FUCK(5);FUCK(6);FUCK(7);FUCK(8);FUCK(9);FUCK(10);FUCK(11);FUCK(12);FUCK(13);FUCK(14);FUCK(15);FUCK(16);FUCK(17);FUCK(18);FUCK(19);FUCK(20);FUCK(21);FUCK(22);FUCK(23);FUCK(24);FUCK(25);FUCK(26);FUCK(27);FUCK(28);FUCK(29);FUCK(30);FUCK(31);FUCK(32);FUCK(33);FUCK(34);FUCK(35);FUCK(36);FUCK(37);FUCK(38);FUCK(39);FUCK(40);FUCK(41);FUCK(42);FUCK(43);FUCK(44);FUCK(45);FUCK(46);FUCK(47);FUCK(48);FUCK(49);FUCK(50);FUCK(51);FUCK(52);FUCK(53);FUCK(54);FUCK(55);FUCK(56);FUCK(57);FUCK(58);FUCK(59);FUCK(60);FUCK(61);FUCK(62);FUCK(63);
    // volatile uint32_t K[64] = {
    // 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    // 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    // 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    // 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    // 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    // 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    // 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    // 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    // 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    // 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    // 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    // 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    // 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    // 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    // 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    // 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    // };
    // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

    register uint32_t a, b, c, d, e, f, g, h;
    uint32_t t[2];

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    #pragma GCC unroll 64

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t a = _word(&ctx->buf[_shw(i, 2)]);
        uint32_t b = _G1(ctx->W[i - 2])  + ctx->W[i - 7] +
                    _G0(ctx->W[i - 15]) + ctx->W[i - 16];
        int sel = i < 16;
        ctx->W[i] = sel * a + !sel * b;
        
        // if (i < 16) {
        //     ctx->W[i] = 
        // } else {
        //     ctx->W[i] = 
        // }

        t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + ctx->W[i];
        t[1] = _S0(a) + _Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
} // _hash


// -----------------------------------------------------------------------------
FN_ void sha256_init(sha256_context *ctx)
{
    ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
    ctx->hash[0] = 0x6a09e667;
    ctx->hash[1] = 0xbb67ae85;
    ctx->hash[2] = 0x3c6ef372;
    ctx->hash[3] = 0xa54ff53a;
    ctx->hash[4] = 0x510e527f;
    ctx->hash[5] = 0x9b05688c;
    ctx->hash[6] = 0x1f83d9ab;
    ctx->hash[7] = 0x5be0cd19;
} // sha256_init


// -----------------------------------------------------------------------------
// FN_ void sha256_hash(sha256_context *ctx, const void *data)
// {
//     const uint8_t *bytes = (const uint8_t *)data;
//     // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(bytes));
//     // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

//     for (size_t i = 0; i < 64; i++) {
//         ctx->buf[i] = bytes[i];
//     }
//     _hash(ctx);
//     _addbits(ctx, sizeof(ctx->buf) * 8);
//     ctx->len = 0;
// } // sha256_hash


// -----------------------------------------------------------------------------
FN_ void sha256_done(sha256_context *ctx, uint8_t *hash)
{
    uint32_t i, j;
    j = 0;
    // _addbits(ctx, ctx->len * 8);

    ctx->buf[j] = 0x80;
    for (i = j + 1; i < sizeof(ctx->buf); i++) {
        ctx->buf[i] = 0x00;
    }

    // ctx->len is always zero here
    // _addbits(ctx, ctx->len * 8);
    ctx->buf[63] = _shb(ctx->bits[0],  0);
    ctx->buf[62] = _shb(ctx->bits[0],  8);
    ctx->buf[61] = _shb(ctx->bits[0], 16);
    ctx->buf[60] = _shb(ctx->bits[0], 24);
    ctx->buf[59] = _shb(ctx->bits[1],  0);
    ctx->buf[58] = _shb(ctx->bits[1],  8);
    ctx->buf[57] = _shb(ctx->bits[1], 16);
    ctx->buf[56] = _shb(ctx->bits[1], 24);
    _hash(ctx);

    for (i = 0, j = 24; i < 4; i++, j -= 8) {
        hash[i +  0] = _shb(ctx->hash[0], j);
        hash[i +  4] = _shb(ctx->hash[1], j);
        hash[i +  8] = _shb(ctx->hash[2], j);
        hash[i + 12] = _shb(ctx->hash[3], j);
        hash[i + 16] = _shb(ctx->hash[4], j);
        hash[i + 20] = _shb(ctx->hash[5], j);
        hash[i + 24] = _shb(ctx->hash[6], j);
        hash[i + 28] = _shb(ctx->hash[7], j);
    }
} // sha256_done

void memcpy(char *dst, char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *dst++ = *src++;
    }
}

__attribute__((noreturn))
void exploit(uint64_t *me){
    void* hash[SHA256_SIZE_BYTES/sizeof(void*)];
    sha256_context ctx;
    sha256_init(&ctx);

    size_t length = &&endcode - &&dohash;
    uint8_t *bytes = (uint8_t *)CODEADDR;

dohash:;
    
    // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(bytes));
    // __CPROVER_assume(__CPROVER_DYNAMIC_OBJECT(ctx));

    for (size_t i = 0; i < 64; i++) {
        ctx.buf[i] = bytes[i];
    }
    _hash(&ctx);
    _addbits(&ctx, sizeof(ctx.buf) * 8);
    ctx.len = 0;

    bytes += 64;
    if (bytes >= CODEADDR + CODELEN) {
        asm volatile("hlt");
    }

    memcpy(&&endcode, &&dohash, length);

endcode:;

    asm volatile(
        ".byte 0x41, 0x41, 0x41, 0x41\n"
        :: [hash] "r" (hash) : "memory"
    );
}