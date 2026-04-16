#include "compat.h"

#if defined(ARCH_X86) && !defined(__WINDOWS__)
size_t apply_mask_sse2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
size_t apply_mask_avx2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
size_t apply_mask_avx512(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
#endif

#if defined(__ARM_NEON) && !defined(__WINDOWS__)
size_t apply_mask_neon(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
#endif

#if defined(ARCH_X86) && !defined(__WINDOWS__) && (defined(__GNUC__) || defined(__clang__))
static int has_avx512f(void)
{
    return __builtin_cpu_supports("avx512f");
}

static int has_avx2(void)
{
    return __builtin_cpu_supports("avx2");
}

static int has_sse2(void)
{
    return __builtin_cpu_supports("sse2");
}
#endif

apply_mask_fn get_apply_mask_fast_fn(void)
{
#if defined(ARCH_X86) && !defined(__WINDOWS__) && (defined(__GNUC__) || defined(__clang__))
    if (has_avx512f())
        return &apply_mask_avx512;
    else if (has_avx2())
        return &apply_mask_avx2;
    else if (has_sse2())
        return &apply_mask_sse2;
    else
        return &apply_mask_8;
#elif defined(__ARM_NEON) && !defined(__WINDOWS__)
    return &apply_mask_neon;
#else
    return &apply_mask_8;
#endif
}

size_t get_apply_mask_fast_alignment(void)
{
#if defined(ARCH_X86) && !defined(__WINDOWS__) && (defined(__GNUC__) || defined(__clang__))
    if (has_avx512f())
        return 64;
    else if (has_avx2())
        return 64;
    else if (has_sse2())
        return 64;
    else
        return 8;
#elif defined(__ARM_NEON) && !defined(__WINDOWS__)
    return 16;
#else
    return 8;
#endif
}
