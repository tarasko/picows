#include "compat.h"

#if defined(ARCH_NEON) && !defined(_WIN32)
#include <arm_neon.h>

size_t apply_mask_neon(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask, uint8_t* output)
{
    typedef uint8x16_t int_x;
    const size_t reg_size = 16;
    const size_t input_len_trunc = (input_len - start_pos) & ~(reg_size - 1);
    const int_x mask_x = vreinterpretq_u8_u32(vdupq_n_u32(mask));

    for (size_t i = start_pos; i < start_pos + input_len_trunc; i += reg_size)
    {
        int_x in = vld1q_u8(input  + i);
        int_x out = veorq_u8(in, mask_x);
        vst1q_u8(output + i, out);
    }

    return start_pos + input_len_trunc;
}
#endif
