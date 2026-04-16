#include "compat.h"

#if defined(ARCH_X86)
#include <immintrin.h>

size_t apply_mask_avx512(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef __m512i int_x;
    const size_t input_len_trunc = (input_len - start_pos) & ~(64 - 1);
    const int_x mask_x = _mm512_set1_epi32(mask);

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += 64)
    {
        int_x in = _mm512_load_si512((int_x *)(input  + i));
        int_x out = _mm512_xor_si512(in, mask_x);
        _mm512_stream_si512((int_x *)(output + i), out);
    }

    return start_pos + input_len_trunc;
}
#endif
