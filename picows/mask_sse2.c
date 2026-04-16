#include "compat.h"

#if defined(ARCH_X86) && !defined(__WINDOWS__)
#include <emmintrin.h>

size_t apply_mask_sse2(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef __m128i int_x;
    const size_t input_len_trunc = (input_len - start_pos) & ~(64 - 1);
    const int_x mask_x = _mm_set1_epi32(mask);

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += 64)
    {
        int_x in1 = _mm_load_si128((int_x *)(input + i));
        int_x in2 = _mm_load_si128((int_x *)(input + i + 16));
        int_x in3 = _mm_load_si128((int_x *)(input + i + 32));
        int_x in4 = _mm_load_si128((int_x *)(input + i + 48));
        int_x out1 = _mm_xor_si128(in1, mask_x);
        int_x out2 = _mm_xor_si128(in2, mask_x);
        int_x out3 = _mm_xor_si128(in3, mask_x);
        int_x out4 = _mm_xor_si128(in4, mask_x);
        _mm_stream_si128((int_x *)(output + i), out1);
        _mm_stream_si128((int_x *)(output + i + 16), out2);
        _mm_stream_si128((int_x *)(output + i + 32), out3);
        _mm_stream_si128((int_x *)(output + i + 48), out4);
    }

    return start_pos + input_len_trunc;
}
#endif
