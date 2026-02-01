#pragma once

#include <errno.h>

#ifndef EWOULDBLOCK
    #define EWOULDBLOCK EAGAIN
#endif

#ifndef ESHUTDOWN
    #define ESHUTDOWN EPIPE
#endif

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
    #define __WINDOWS__
    #define PLATFORM_IS_WINDOWS 1
#else
    #define PLATFORM_IS_WINDOWS 0
#endif

#ifdef __APPLE__
    #define PLATFORM_IS_APPLE 1
#else
    #define PLATFORM_IS_APPLE 0
#endif

#ifdef __linux__
    #define PLATFORM_IS_LINUX 1
#else
    #define PLATFORM_IS_LINUX 0
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #define ARCH_X86
#endif

#if defined(__aarch64__) || defined(__arm__) || defined(_M_ARM) || defined(_M_ARM64)
  #define ARCH_ARM
#endif

#if defined(__linux__)
    #include <arpa/inet.h>
    #include <endian.h>
#elif defined(__APPLE__)
    #include <arpa/inet.h>
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define htobe64(x) OSSwapHostToBigInt64(x)
#elif defined(__OpenBSD__)
    #include <arpa/inet.h>
    #include <sys/endian.h>
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
    #include <arpa/inet.h>
    #include <sys/endian.h>
    #define be64toh(x) betoh64(x)
#elif defined(__WINDOWS__)
    #include <winsock2.h>
    #if BYTE_ORDER == LITTLE_ENDIAN
        #define be64toh(x) ntohll(x)
        #define htobe64(x) htonll(x)
    #elif BYTE_ORDER == BIG_ENDIAN
        #define be64toh(x) (x)
        #define htobe64(x) (x)
    #endif
#else
    error byte order not supported
#endif

#ifdef __WINDOWS__

    #include <winsock2.h>
    #define PICOWS_SOCKET_ERROR SOCKET_ERROR

    static inline double picows_get_monotonic_time(void)
    {
        LARGE_INTEGER frequency, counter;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
        return (double)counter.QuadPart / frequency.QuadPart;
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <time.h>

    #define PICOWS_SOCKET_ERROR -1

    static inline double picows_get_monotonic_time(void)
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
    }
#endif

typedef size_t (*mask_payload_fn)(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask);

static inline size_t rotate_right(size_t value, size_t bytes)
{
    size_t bits = (bytes % 4) * 8;
    return (value >> bits) | (value << (32 - bits));
}

static inline size_t mask_payload_32(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
{
    typedef uint64_t int_x;
    const size_t reg_size = 4;
    const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);

    const int_x mask_x = mask;

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        *(int_x*)(input + i) ^= mask_x;

    return start_pos + input_len_trunc;
}

static inline size_t mask_payload_1(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
{
    uint8_t* mask_ptr = (uint8_t*)&mask;

    for (size_t i = start_pos, k = 0; i < input_len; i += 1, k += 1)
        input[i] ^= mask_ptr[k % 4];

    return input_len;
}

static inline size_t mask_misaligned(uint8_t* input, size_t input_len, uint32_t mask, size_t alignment)
{
    size_t ptr_value = (size_t)input;
    size_t misalignment = fmin(alignment - (ptr_value % alignment), input_len);

    mask_payload_1(input, misalignment, 0, mask);

    return misalignment;
}

static size_t mask_payload_64(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
{
    typedef uint64_t int_x;
    const size_t reg_size = 8;
    const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);

    const int_x mask_x = ((int_x)mask << 32) | (int_x)mask;

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        *(int_x*)(input + i) ^= mask_x;

    return start_pos + input_len_trunc;
}

#if defined(ARCH_X86) && (defined(__GNUC__) || defined(__clang__))
    #include <emmintrin.h>
    #include <immintrin.h>

    static int has_avx512f(void) { return __builtin_cpu_supports("avx512f"); }
    static int has_avx2(void) { return __builtin_cpu_supports("avx2"); }
    static int has_sse2(void) { return __builtin_cpu_supports("sse2"); }

    __attribute__((target("avx512f")))
    static size_t mask_payload_avx512(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
    {
        typedef __m512i int_x;
        const size_t reg_size = 64;
        const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);

        const int_x mask_x = _mm512_set1_epi32(mask);

        for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        {
            int_x in = _mm512_load_si512((int_x *)(input  + i));
            int_x out = _mm512_xor_si512(in, mask_x);
            _mm512_store_si512((int_x *)(input + i), out);
        }

        return start_pos + input_len_trunc;
    }

    __attribute__((target("avx2")))
    static size_t mask_payload_avx2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
    {
        typedef __m256i int_x;
        const size_t reg_size = 32;
        const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);

        const int_x mask_x = _mm256_set1_epi32(mask);

        for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        {
            int_x in = _mm256_load_si256((int_x *)(input  + i));
            int_x out = _mm256_xor_si256(in, mask_x);
            _mm256_store_si256((int_x *)(input + i), out);
        }

        return start_pos + input_len_trunc;
    }

    __attribute__((target("sse2")))
    static size_t mask_payload_sse2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
    {
        typedef __m128i int_x;
        const size_t reg_size = 16;
        const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);

        const int_x mask_x = _mm_set1_epi32(mask);

        for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        {
            int_x in = _mm_load_si128((int_x *)(input  + i));
            int_x out = _mm_xor_si128(in, mask_x);
            _mm_store_si128((int_x *)(input + i), out);
        }

        return start_pos + input_len_trunc;
    }

    static mask_payload_fn get_mask_payload_fn()
    {
        if (has_avx512f())
            return &mask_payload_avx512;
        else if (has_avx2())
            return &mask_payload_avx2;
        else if (has_sse2())
            return &mask_payload_sse2;
        else
            return &mask_payload_64;
    }

    static size_t get_mask_payload_alignment()
    {
        if (has_avx512f())
            return 64;
        else if (has_avx2())
            return 32;
        else if (has_sse2())
            return 16;
        else
            return 8;
    }
#else
    static mask_payload_fn get_mask_payload_fn()
    {
        return &mask_payload_64;
    }

    static size_t get_mask_payload_alignment()
    {
        return 8;
    }
#endif
