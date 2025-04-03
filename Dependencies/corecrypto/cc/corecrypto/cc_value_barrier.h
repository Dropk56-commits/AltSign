/* Copyright (c) (2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_VALUE_BARRIER_H_
#define _CORECRYPTO_CC_VALUE_BARRIER_H_

extern volatile const uint64_t cc_value_barrier_zero;

CC_INLINE CC_WARN_RESULT
int16_t cc_value_barrier_int16(int16_t x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (int16_t)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
int64_t cc_value_barrier_int64(int64_t x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (int64_t)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
uint8_t cc_value_barrier_uint8(uint8_t x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (uint8_t)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
uint32_t cc_value_barrier_uint32(uint32_t x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (uint32_t)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
uint64_t cc_value_barrier_uint64(uint64_t x)
{
 #if CC_HAS_EXTENDED_ASM && (CCN_UNIT_SIZE == 8)
    __asm__ __volatile__("" : "+r"(x));
 #else
    x ^= cc_value_barrier_zero;
 #endif
    return x;
}

CC_INLINE CC_WARN_RESULT
unsigned cc_value_barrier_unsigned(unsigned x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (unsigned)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
int cc_value_barrier_int(int x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (int)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
size_t cc_value_barrier_size_t(size_t x)
{
#if CC_HAS_EXTENDED_ASM
    __asm__ __volatile__("" : "+r"(x));
#else
    x ^= (size_t)cc_value_barrier_zero;
#endif
    return x;
}

CC_INLINE CC_WARN_RESULT
int16_t cc_neg_mask_int16(int16_t x)
{
    return cc_value_barrier_int16(x >> 15);
}

CC_INLINE CC_WARN_RESULT
int64_t cc_neg_mask_int64(int64_t x)
{
    return cc_value_barrier_int64(x >> 63);
}

CC_INLINE CC_WARN_RESULT
int cc_neg_mask_int(int x)
{
    return cc_value_barrier_int(x >> (sizeof(int) * 8 - 1));
}

CC_INLINE CC_WARN_RESULT
uint8_t cc_bit_to_mask_uint8(uint8_t x)
{
    cc_assert((x >> 1) == 0);
    return (uint8_t)-cc_value_barrier_uint8(x);
}

CC_INLINE CC_WARN_RESULT
uint32_t cc_bit_to_mask_uint32(uint32_t x)
{
    cc_assert((x >> 1) == 0);
    return (uint32_t)-cc_value_barrier_uint32(x);
}

CC_INLINE CC_WARN_RESULT
uint64_t cc_bit_to_mask_uint64(uint64_t x)
{
    cc_assert((x >> 1) == 0);
    return (uint64_t)-cc_value_barrier_uint64(x);
}

CC_INLINE CC_WARN_RESULT
unsigned cc_bit_to_mask_unsigned(unsigned x)
{
    cc_assert((x >> 1) == 0);
    return (unsigned)-cc_value_barrier_unsigned(x);
}

CC_INLINE CC_WARN_RESULT
int cc_bit_to_mask_int(int x)
{
    cc_assert((x >> 1) == 0);
    return (int)-cc_value_barrier_int(x);
}

CC_INLINE CC_WARN_RESULT
size_t cc_bit_to_mask_size_t(size_t x)
{
    cc_assert((x >> 1) == 0);
    return (size_t)-cc_value_barrier_size_t(x);
}

CC_INLINE CC_WARN_RESULT
uint8_t cc_nonzero_mask_uint8(uint8_t x)
{
    return cc_bit_to_mask_uint8((x | (uint8_t)-x) >> 7);
}

CC_INLINE CC_WARN_RESULT
uint32_t cc_nonzero_mask_uint32(uint32_t x)
{
    return cc_bit_to_mask_uint32((x | (uint32_t)-x) >> 31);
}

CC_INLINE CC_WARN_RESULT
uint64_t cc_nonzero_mask_uint64(uint64_t x)
{
    return cc_bit_to_mask_uint64((x | (uint64_t)-x) >> 63);
}

CC_INLINE CC_WARN_RESULT
unsigned cc_nonzero_mask_unsigned(unsigned x)
{
    return cc_bit_to_mask_unsigned((x | (unsigned)-x) >> (sizeof(unsigned) * 8 - 1));
}

CC_INLINE CC_WARN_RESULT
int cc_nonzero_mask_int(int x)
{
    return (int)cc_nonzero_mask_unsigned((unsigned)x);
}

CC_INLINE CC_WARN_RESULT
size_t cc_nonzero_mask_size_t(size_t x)
{
    return cc_bit_to_mask_size_t((x | (size_t)-x) >> (sizeof(size_t) * 8 - 1));
}

CC_INLINE CC_WARN_RESULT
uint8_t cc_eq_mask_uint8(uint8_t a, uint8_t b)
{
    return (uint8_t)~cc_nonzero_mask_uint8(a ^ b);
}

CC_INLINE CC_WARN_RESULT
uint32_t cc_eq_mask_uint32(uint32_t a, uint32_t b)
{
    return (uint32_t)~cc_nonzero_mask_uint32(a ^ b);
}

CC_INLINE CC_WARN_RESULT
uint64_t cc_eq_mask_uint64(uint64_t a, uint64_t b)
{
    return (uint64_t)~cc_nonzero_mask_uint64(a ^ b);
}

CC_INLINE CC_WARN_RESULT
size_t cc_eq_mask_size_t(size_t a, size_t b)
{
    return (size_t)~cc_nonzero_mask_size_t(a ^ b);
}

CC_INLINE CC_WARN_RESULT
uint8_t cc_smaller_mask_uint8(uint8_t a, uint8_t b)
{
    return cc_bit_to_mask_uint8((a ^ ((a^b) | ((uint8_t)(a-b) ^ a))) >> 7);
}

CC_INLINE CC_WARN_RESULT
uint32_t cc_smaller_mask_uint32(uint32_t a, uint32_t b)
{
    return cc_bit_to_mask_uint32((a ^ ((a^b) | ((a-b) ^ a))) >> 31);
}

CC_INLINE CC_WARN_RESULT
uint64_t cc_smaller_mask_uint64(uint64_t a, uint64_t b)
{
    return cc_bit_to_mask_uint64((a ^ ((a^b) | ((a-b) ^ a))) >> 63);
}

#endif // _CORECRYPTO_CC_VALUE_BARRIER_H_
