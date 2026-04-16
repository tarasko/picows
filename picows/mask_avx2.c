#include "compat.h"

#if defined(ARCH_X86) && !defined(__WINDOWS__)
#include <immintrin.h>

size_t apply_mask_avx2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef __m256i int_x;
    const size_t input_len_trunc = (input_len - start_pos) & ~(64 - 1);
    const int_x mask_x = _mm256_set1_epi32(mask);

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += 64)
    {
        int_x in1 = _mm256_load_si256((int_x *)(input + i));
        int_x in2 = _mm256_load_si256((int_x *)(input + i + 32));
        int_x out1 = _mm256_xor_si256(in1, mask_x);
        int_x out2 = _mm256_xor_si256(in2, mask_x);
        _mm256_stream_si256((int_x *)(output + i), out1);
        _mm256_stream_si256((int_x *)(output + i + 32), out2);
    }

    return start_pos + input_len_trunc;
}
#endif
