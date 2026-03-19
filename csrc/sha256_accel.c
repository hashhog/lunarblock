/*
 * SHA-256 hardware acceleration for lunarblock
 *
 * Uses Intel SHA-NI instructions when available, falls back to OpenSSL.
 * Based on the pattern from Bitcoin Core's sha256_x86_shani.cpp.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __x86_64__
#include <cpuid.h>
#include <immintrin.h>
#endif

#include <openssl/sha.h>

/* Acceleration type enum */
#define ACCEL_GENERIC 0
#define ACCEL_SHA_NI  1
#define ACCEL_AVX2    2

/* Function pointers for dispatch */
typedef void (*sha256_func_t)(const uint8_t* data, size_t len, uint8_t out[32]);
typedef void (*sha256d_func_t)(const uint8_t* data, size_t len, uint8_t out[32]);

static sha256_func_t sha256_impl = NULL;
static sha256d_func_t sha256d_impl = NULL;
static int accel_type = ACCEL_GENERIC;

/* Generic (OpenSSL) implementation */
static void sha256_generic(const uint8_t* data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
}

static void sha256d_generic(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    SHA256(data, len, tmp);
    SHA256(tmp, 32, out);
}

#ifdef __x86_64__

/* SHA-256 initial state (big-endian) */
static const uint32_t SHA256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* SHA-256 round constants */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Byte-swap mask for converting between big-endian and little-endian */
static const uint8_t SHUF_MASK[16] __attribute__((aligned(16))) = {
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
};

/*
 * SHA-NI accelerated SHA-256 transform for a single 64-byte block.
 * Based on Intel's reference and Bitcoin Core's implementation.
 */
__attribute__((target("sha,sse4.1")))
static void sha256_transform_shani(uint32_t state[8], const uint8_t* data) {
    __m128i state0, state1;
    __m128i msg, tmp;
    __m128i msg0, msg1, msg2, msg3;
    __m128i abef_save, cdgh_save;
    __m128i shuf_mask = _mm_load_si128((const __m128i*)SHUF_MASK);

    /* Load initial state */
    /* state[0..3] = ABCD, state[4..7] = EFGH */
    tmp = _mm_loadu_si128((const __m128i*)(state));
    state1 = _mm_loadu_si128((const __m128i*)(state + 4));

    /* The SHA-NI instructions expect state in a specific order:
     * state0 = CDAB, state1 = GHEF (after shuffle) */
    tmp = _mm_shuffle_epi32(tmp, 0xB1);     /* CDAB */
    state1 = _mm_shuffle_epi32(state1, 0x1B); /* HGFE -> EFGH */
    state0 = _mm_alignr_epi8(tmp, state1, 8); /* ABEF */
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); /* CDGH */

    /* Save current state for later addition */
    abef_save = state0;
    cdgh_save = state1;

    /* Rounds 0-3 */
    msg0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data)), shuf_mask);
    msg = _mm_add_epi32(msg0, _mm_set_epi64x(0xe9b5dba5b5c0fbcfULL, 0x71374491428a2f98ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    /* Rounds 4-7 */
    msg1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 16)), shuf_mask);
    msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xab1c5ed5923f82a4ULL, 0x59f111f13956c25bULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 8-11 */
    msg2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 32)), shuf_mask);
    msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x550c7dc3243185beULL, 0x12835b01d807aa98ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 12-15 */
    msg3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 48)), shuf_mask);
    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xc19bf1749bdc06a7ULL, 0x80deb1fe72be5d74ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 16-19 */
    msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x240ca1cc0fc19dc6ULL, 0xefbe4786e49b69c1ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 20-23 */
    msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76f988da5cb0a9dcULL, 0x4a7484aa2de92c6fULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 24-27 */
    msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xbf597fc7b00327c8ULL, 0xa831c66d983e5152ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 28-31 */
    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706ca6351ULL, 0xd5a79147c6e00bf3ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 32-35 */
    msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x53380d134d2c6dfcULL, 0x2e1b213827b70a85ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 36-39 */
    msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722c8581c2c92eULL, 0x766a0abb650a7354ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 40-43 */
    msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xc76c51a3c24b8b70ULL, 0xa81a664ba2bfe8a1ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 44-47 */
    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106aa070f40e3585ULL, 0xd6990624d192e819ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 48-51 */
    msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x34b0bcb52748774cULL, 0x1e376c0819a4c116ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 52-55 */
    msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682e6ff35b9cca4fULL, 0x4ed8aa4a391c0cb3ULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    /* Rounds 56-59 */
    msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8cc7020884c87814ULL, 0x78a5636f748f82eeULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    /* Rounds 60-63 */
    msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xc67178f2bef9a3f7ULL, 0xa4506ceb90befffaULL));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    /* Add saved state */
    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);

    /* Unshuffle state back to ABCDEFGH order */
    tmp = _mm_shuffle_epi32(state0, 0x1B);    /* FEBA */
    state1 = _mm_shuffle_epi32(state1, 0xB1); /* DCHG */
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); /* DCBA */
    state1 = _mm_alignr_epi8(state1, tmp, 8);    /* HGFE */

    /* Store state */
    _mm_storeu_si128((__m128i*)state, state0);
    _mm_storeu_si128((__m128i*)(state + 4), state1);
}

/*
 * Full SHA-256 with SHA-NI acceleration.
 * Handles padding and multi-block messages.
 */
__attribute__((target("sha,sse4.1")))
static void sha256_shani(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t state[8];
    uint8_t buffer[64];
    size_t remaining = len;
    const uint8_t* ptr = data;

    /* Initialize state */
    memcpy(state, SHA256_INIT, sizeof(state));

    /* Process full 64-byte blocks */
    while (remaining >= 64) {
        sha256_transform_shani(state, ptr);
        ptr += 64;
        remaining -= 64;
    }

    /* Pad the final block(s) */
    memset(buffer, 0, 64);
    memcpy(buffer, ptr, remaining);
    buffer[remaining] = 0x80;

    if (remaining >= 56) {
        /* Need two blocks for padding */
        sha256_transform_shani(state, buffer);
        memset(buffer, 0, 64);
    }

    /* Append length in bits (big-endian) */
    uint64_t bit_len = (uint64_t)len * 8;
    buffer[56] = (uint8_t)(bit_len >> 56);
    buffer[57] = (uint8_t)(bit_len >> 48);
    buffer[58] = (uint8_t)(bit_len >> 40);
    buffer[59] = (uint8_t)(bit_len >> 32);
    buffer[60] = (uint8_t)(bit_len >> 24);
    buffer[61] = (uint8_t)(bit_len >> 16);
    buffer[62] = (uint8_t)(bit_len >> 8);
    buffer[63] = (uint8_t)(bit_len);

    sha256_transform_shani(state, buffer);

    /* Output hash (convert to big-endian bytes) */
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

/*
 * Double SHA-256 with SHA-NI acceleration.
 */
__attribute__((target("sha,sse4.1")))
static void sha256d_shani(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha256_shani(data, len, tmp);
    sha256_shani(tmp, 32, out);
}

/*
 * CPUID detection for SHA-NI and AVX2.
 */
static int detect_cpu_features(int* has_sha, int* has_avx2) {
    unsigned int eax, ebx, ecx, edx;

    *has_sha = 0;
    *has_avx2 = 0;

    /* Check extended features (leaf 7, subleaf 0) */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        /* SHA-NI is bit 29 of EBX */
        *has_sha = (ebx >> 29) & 1;
        /* AVX2 is bit 5 of EBX */
        *has_avx2 = (ebx >> 5) & 1;
    }

    return 1;
}

#endif /* __x86_64__ */

/*
 * Initialize and select the best available implementation.
 * Returns: 0 = generic, 1 = SHA-NI, 2 = AVX2 (reserved for future use)
 */
int sha256_accel_init(void) {
#ifdef __x86_64__
    int has_sha = 0, has_avx2 = 0;

    detect_cpu_features(&has_sha, &has_avx2);

    if (has_sha) {
        sha256_impl = sha256_shani;
        sha256d_impl = sha256d_shani;
        accel_type = ACCEL_SHA_NI;
        return ACCEL_SHA_NI;
    }

    if (has_avx2) {
        /* For now, AVX2 path still uses generic;
         * could add SIMD multi-buffer SHA-256 later */
        sha256_impl = sha256_generic;
        sha256d_impl = sha256d_generic;
        accel_type = ACCEL_AVX2;
        return ACCEL_AVX2;
    }
#endif

    sha256_impl = sha256_generic;
    sha256d_impl = sha256d_generic;
    accel_type = ACCEL_GENERIC;
    return ACCEL_GENERIC;
}

/*
 * Public API: SHA-256
 */
void sha256_accel(const uint8_t* data, size_t len, uint8_t out[32]) {
    if (sha256_impl == NULL) {
        sha256_accel_init();
    }
    sha256_impl(data, len, out);
}

/*
 * Public API: Double SHA-256
 */
void sha256d_accel(const uint8_t* data, size_t len, uint8_t out[32]) {
    if (sha256d_impl == NULL) {
        sha256_accel_init();
    }
    sha256d_impl(data, len, out);
}
