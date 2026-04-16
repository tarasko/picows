#include "compat.h"

#if defined(ARCH_X86)
size_t apply_mask_sse2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
size_t apply_mask_avx2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
size_t apply_mask_avx512(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);

#if defined(__GNUC__) || defined(__clang__)
// gcc/clang provide convenient __builtin_cpu_supports

static int has_avx512f(void) { return __builtin_cpu_supports("avx512f"); }
static int has_avx2(void) { return __builtin_cpu_supports("avx2"); }
static int has_sse2(void) { return __builtin_cpu_supports("sse2"); }

#elif defined(_MSC_VER)
// msvc is pain, use __cpuidex to get raw information about cpu capabilities

#include <intrin.h>

static void get_cpuid(int leaf, int subleaf, int regs[4])
{
    __cpuidex(regs, leaf, subleaf);
}

static int get_max_cpuid_leaf(void)
{
    int regs[4];
    get_cpuid(0, 0, regs);
    return regs[0];
}

static int has_os_avx_state(void)
{
    int regs[4];
    get_cpuid(1, 0, regs);
    if ((regs[2] & (1 << 27)) == 0)
        return 0;

    return (_xgetbv(0) & 0x6) == 0x6;
}

static int has_os_avx512_state(void)
{
    int regs[4];
    get_cpuid(1, 0, regs);
    if ((regs[2] & (1 << 27)) == 0)
        return 0;

    return (_xgetbv(0) & 0xe6) == 0xe6;
}

static int has_avx512f(void)
{
    int regs[4];
    if (get_max_cpuid_leaf() < 7 || !has_os_avx512_state())
        return 0;

    get_cpuid(7, 0, regs);
    return (regs[1] & (1 << 16)) != 0;
}

static int has_avx2(void)
{
    int regs[4];
    if (get_max_cpuid_leaf() < 7 || !has_os_avx_state())
        return 0;

    get_cpuid(1, 0, regs);
    if ((regs[2] & (1 << 28)) == 0)
        return 0;

    get_cpuid(7, 0, regs);
    return (regs[1] & (1 << 5)) != 0;
}

static int has_sse2(void)
{
    int regs[4];
    if (get_max_cpuid_leaf() < 1)
        return 0;

    get_cpuid(1, 0, regs);
    return (regs[3] & (1 << 26)) != 0;
}

#else

static int has_avx512f(void) { return 0; }
static int has_avx2(void) { return 0; }
static int has_sse2(void) { return 0; }

#endif
#endif // defined(ARCH_X86)

#if defined(ARCH_NEON)
size_t apply_mask_neon(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output);
#endif

const char* get_apply_mask_fast_impl_name(void)
{
#if defined(ARCH_X86)
    if (has_avx512f())
        return "avx512";
    else if (has_avx2())
        return "avx2";
    else if (has_sse2())
        return "sse2";
#elif defined(ARCH_NEON)
    return "neon";
#endif
    return "generic";
}

apply_mask_fn get_apply_mask_fast_fn(void)
{
#if defined(ARCH_X86)
    if (has_avx512f())
        return &apply_mask_avx512;
    else if (has_avx2())
        return &apply_mask_avx2;
    else if (has_sse2())
        return &apply_mask_sse2;
#elif defined(ARCH_NEON)
    return &apply_mask_neon;
#endif
    return &apply_mask_8;
}

size_t get_apply_mask_fast_alignment(void)
{
#if defined(ARCH_X86)
    if (has_avx512f())
        return 64;
    else if (has_avx2())
        return 64;
    else if (has_sse2())
        return 64;
#elif defined(ARCH_NEON)
    return 16;
#endif
    return 8;
}

