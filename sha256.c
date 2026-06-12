#include "sha256.h"
#include <string.h>

static const uint32_t SHA_256_K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static inline uint32_t sha_ROTR32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

//CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
static inline uint32_t sha_CH(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}
//MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
static inline uint32_t sha_MAJ(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
//BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
static inline uint32_t sha_BSIG0(uint32_t x)
{
    return sha_ROTR32(x, 2) ^ sha_ROTR32(x, 13) ^ sha_ROTR32(x, 22);
}
//BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
static inline uint32_t sha_BSIG1(uint32_t x)
{
    return sha_ROTR32(x, 6) ^ sha_ROTR32(x, 11) ^ sha_ROTR32(x, 25);
}
//SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
static inline uint32_t sha_SSIG0(uint32_t x)
{
    return sha_ROTR32(x, 7) ^ sha_ROTR32(x, 18) ^ (x >> 3);
}
//SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
static inline uint32_t sha_SSIG1(uint32_t x)
{
    return sha_ROTR32(x, 17) ^ sha_ROTR32(x, 19) ^ (x >> 10);
}

static void sha256_compress(uint32_t* restrict state, const uint8_t* restrict block)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
    {
        w[i] = (uint32_t)block[4 * i] << 24
            | (uint32_t)block[4 * i + 1] << 16
            | (uint32_t)block[4 * i + 2] << 8
            | (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 64; ++i)
    {
        w[i] = sha_SSIG1(w[i - 2]) + w[i - 7] + sha_SSIG0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i)
    {
        uint32_t t1 = h + sha_BSIG1(e) + sha_CH(e, f, g) + SHA_256_K[i] + w[i];
        uint32_t t2 = sha_BSIG0(a) + sha_MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(uint32_t* restrict dst, const uint8_t* restrict src, size_t len)
{
    if (__builtin_mul_overflow_p(len, (uint64_t)8, (uint64_t)0))
    {
        return;
    }
    const uint64_t len_bits = len * 8;
    const size_t full_blocks = len >> 6;
    const size_t rem = len & 63;

    uint8_t rembuf[64 * 2] = {0};
    memcpy(rembuf, src + (full_blocks * 64), rem);
    rembuf[rem] = 0x80U;

    const int len_idx = (rem < 56 ? 56 : 64 + 56);
    rembuf[len_idx] = (uint8_t)(len_bits >> 56 & 0xFF);
    rembuf[len_idx + 1] = (uint8_t)(len_bits >> 48 & 0xFF);
    rembuf[len_idx + 2] = (uint8_t)(len_bits >> 40 & 0xFF);
    rembuf[len_idx + 3] = (uint8_t)(len_bits >> 32 & 0xFF);
    rembuf[len_idx + 4] = (uint8_t)(len_bits >> 24 & 0xFF);
    rembuf[len_idx + 5] = (uint8_t)(len_bits >> 16 & 0xFF);
    rembuf[len_idx + 6] = (uint8_t)(len_bits >> 8 & 0xFF);
    rembuf[len_idx + 7] = (uint8_t)(len_bits & 0xFF);

    uint32_t state[8] = {
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19
    };

    for (size_t block_idx = 0; block_idx < full_blocks; ++block_idx)
    {
        sha256_compress(state, src + (block_idx * 64));
    }
    sha256_compress(state, rembuf);
    if (rem >= 56) sha256_compress(state, rembuf + 64);

    dst[0] = state[0];
    dst[1] = state[1];
    dst[2] = state[2];
    dst[3] = state[3];
    dst[4] = state[4];
    dst[5] = state[5];
    dst[6] = state[6];
    dst[7] = state[7];
}