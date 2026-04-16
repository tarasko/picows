#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

// __x86_64__ defined by GCC/Clang when compiling for 64-bit x86, also called x86-64 or AMD64.
// __i386__   defined by GCC/Clang when compiling for 32-bit x86.
// _M_X64     defined by MSVC when compiling for 64-bit x86.
// _M_IX86    defined by MSVC when compiling for 32-bit x86.
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
  #define ARCH_X86
#endif

// __ARM_NEON   NEON intrinsics enabled (gcc, clang)
// __ARM_NEON__ NEON intrinsics enabled, alternate spelling (some other compilers)
// __aarch64__  defined by GCC/Clang compiling for 64-bit ARM, NEON/AdvSIMD normally baseline
// _M_ARM64     defined by MSVC when compiling for Windows ARM64, NEON is a baseline architecture
#if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__) || defined(_M_ARM64)
  #define ARCH_NEON
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define MAYBE_UNUSED __attribute__((unused))
#else
  #define MAYBE_UNUSED
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
#elif defined(_WIN32)
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

#define PICOWS_MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef _WIN32
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

typedef size_t (*apply_mask_fn)(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);

const char*     get_apply_mask_fast_impl_name(void);
apply_mask_fn   get_apply_mask_fast_fn(void);
size_t          get_apply_mask_fast_alignment(void);

static inline size_t rotate_right(uint32_t value, size_t num_bytes)
{
    const uint32_t bits = (num_bytes % 4) * 8;
    return (value >> bits) | (value << (32 - bits));
}

static inline size_t apply_mask_1(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    uint8_t* mask_ptr = (uint8_t*)&mask;

    for (size_t i = start_pos, k = 0; i < input_len; i += 1, k += 1)
        output[i] = input[i] ^ mask_ptr[k % 4];

    return input_len;
}

static inline size_t apply_mask_4(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef uint64_t int_x;
    const size_t reg_size = 4;
    const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);
    const int_x mask_x = mask;

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
        *(int_x*)(output + i) = *(int_x*)(input + i) ^ mask_x;

    return start_pos + input_len_trunc;
}

static inline size_t mask_misaligned_bytes_at_front(uint8_t* input, size_t input_len, uint32_t mask, size_t alignment, uint8_t** output)
{
    // Calculate how many bytes at front are not aligned to the target alignment.
    // Shift output pointer forward, so that it has the same misalignment
    // Apply mask to misaligned bytes and write result at the new output pointer
    const size_t input_ptr_value = (size_t)input;
    const size_t output_ptr_value = (size_t)*output;
    const size_t input_misalignment = alignment - (input_ptr_value % alignment);
    const size_t output_misalignment = alignment - (output_ptr_value % alignment);
    const size_t num_misaligned_bytes = PICOWS_MIN(input_misalignment, input_len);

    if (output_misalignment > input_misalignment)
        *output += (output_misalignment - input_misalignment);
    else if (input_misalignment > output_misalignment)
        *output += (alignment + output_misalignment - input_misalignment);

    return apply_mask_1(input, num_misaligned_bytes, 0, mask, *output);
}

MAYBE_UNUSED
static inline size_t apply_mask_8(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef uint64_t int_x;
    const size_t reg_size = 8;
    const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);
    const int_x mask_x = ((int_x)mask << 32) | (int_x)mask;

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
       *(int_x*)(output + i) = *(int_x*)(input + i) ^ mask_x;

    return start_pos + input_len_trunc;
}
