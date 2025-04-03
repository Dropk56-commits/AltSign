/* Copyright (c) (2019,2021-2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_INTERNAL_H_
#define _CORECRYPTO_CC_INTERNAL_H_

#include <corecrypto/cc_priv.h>
#include "cc_runtime_config.h"

#if CC_XNU_KERNEL_PRIVATE
#elif CC_EFI
#elif CC_KERNEL
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

#include <stdarg.h>

#include "cc_macros.h"
#include "cc_value_barrier.h"

#if defined(__INT_MAX__)
 #define CC_INT_MAX __INT_MAX__
#else
 #include <limits.h>
 #define CC_INT_MAX INT_MAX
#endif

#if CC_EFI
#include "cc_efi_shim.h"
    int cc_memcmp(const void *buf1, const void *buf2, size_t len);
#else
    #define cc_memcmp(buf1, buf2, len) memcmp(buf1, buf2, len)
#endif

extern bool cc_rdrand(uint64_t *rand);

#if CC_BUILT_FOR_TESTING
extern bool (*cc_rdrand_mock)(uint64_t *rand);

extern void (*cc_abort_mock)(const char *msg);
#endif


#if CC_BUILT_FOR_TESTING && CC_DIT_WITH_SB_MAYBE_SUPPORTED
 #define CC_TEST_ASSERT_NO_NESTED_DITS 1
 #define CC_TEST_ASSERT_DIT_ENABLED 1
#else
 #define CC_TEST_ASSERT_NO_NESTED_DITS 0
 #define CC_TEST_ASSERT_DIT_ENABLED 0
#endif

#if CC_DIT_WITH_SB_MAYBE_SUPPORTED

#include "cc_timing_safe.h"

/*
  We'll test two conditions in our code:
  1. That DIT is not called in a nested fashion
  2. That DIT is enabled in "internal" functions that assume DIT
 
  To make it easier for corecrypto developers to ensure these properties
  we'll introduce some debug functionality to produce backtraces when they
  occur. This functionality is detailed below with the function `emit_backtrace`.
 */
#if CC_TEST_ASSERT_NO_NESTED_DITS || CC_TEST_ASSERT_DIT_ENABLED
#include <execinfo.h>
#include "cc_debug.h"
CC_INLINE void emit_backtrace(void)
{
    void *callstack[128];
    ssize_t frames = backtrace(callstack, 128);
    char **symbols = backtrace_symbols(callstack, (int) frames);
    for (int i = 0; i < frames; i++) {
        cc_printf("%s", symbols[i]);
        cc_printf("\n");
    }
    free(symbols);
}
#endif // CC_TEST_ASSERT_NO_NESTED_DITS || CC_TEST_ASSERT_DIT_ENABLED

/*
  We introduce some functions to *disable* nested DIT checks to aid
  in our transition to no nested DIT calls. Specifically, it can be
  convenient to temporarily disable these checks to make progress in
  porting (de-nesting) code.
 */
#if CC_TEST_ASSERT_NO_NESTED_DITS
void cc_test_disable_nested_dit_checks(void);
void cc_test_enable_nested_dit_checks(void);
bool cc_test_nested_dit_checks_enabled(void);
#endif

/*
 We also introduce some functionality to "enable" DIT without
 actually enabling DIT. This helps in some test functions that
 test internal functions that assume DIT is enabled. Instead of
 turning on DIT for the entire function, we can target specific
 locations to "enable" it.
 */
#if CC_TEST_ASSERT_DIT_ENABLED
void cc_test_disable_dit_asserts(void);
void cc_test_enable_dit_asserts(void);
bool cc_test_dit_asserts_enabled(void);
#endif

CC_INLINE timingsafe_token_t cc_enable_dit_with_sb(void)
{
    #if CC_TEST_ASSERT_NO_NESTED_DITS
    // We'll necessarily check for nested DIT calls when we attempt to enable DIT.
    if (timingsafe_is_enabled() && cc_test_nested_dit_checks_enabled()) {
        cc_printf("Nested DIT calls!\n");
        emit_backtrace();
        cc_assert(1 == 2);
    }
    #endif // CC_TEST_ASSERT_NO_NESTED_DITS
    return timingsafe_enable_if_supported();
}

void cc_disable_dit_with_sb(volatile timingsafe_token_t *cc_unsafe_indexable token);

/*
 Finally we add functionality to ensure that DIT is enabled in
 internal functions that expect it to be enabled.
 */
#if CC_TEST_ASSERT_DIT_ENABLED
CC_INLINE void cc_test_ensure_dit_is_enabled(void)
{
    if (CC_HAS_DIT() && !timingsafe_is_enabled() && cc_test_dit_asserts_enabled()) {
        cc_printf("Internal function should have DIT enabled!\n");
        emit_backtrace();
        cc_assert(1 == 3);
    }
}
#else
CC_INLINE void cc_test_ensure_dit_is_enabled(void) { }
#endif // CC_TEST_ASSERT_DIT_ENABLED

#endif /* CC_TEST_ASSERT_NO_NESTED_DITS */

#if CC_DIT_MAYBE_SUPPORTED

// Use the DIT register's encoded name to avoid assembler
// complaints when compiling for ARM64 before v8.4.
#define CC_DIT_REGISTER "s3_3_c4_c2_5"

#define CC_DIT_BIT (1U << 24)

CC_INLINE bool cc_is_dit_enabled(void)
{
    return __builtin_arm_rsr64(CC_DIT_REGISTER) & CC_DIT_BIT;
}

CC_INLINE bool cc_enable_dit(void)
{
    if (!CC_HAS_DIT()) {
        return false;
    }

    // DIT might have already been enabled by another corecrypto function, in
    // that case that function is responsible for disabling DIT when returning.
    //
    // This also covers when code _outside_ corecrypto enabled DIT before
    // calling us. In that case we're not responsible for disabling it either.
    if (cc_is_dit_enabled()) {
        return false;
    }

    // Encoding of <msr dit, #1>.
    __asm__ __volatile__(".long 0xd503415f");

#if CC_BUILT_FOR_TESTING
    // Check that DIT was enabled.
    cc_try_abort_if(!cc_is_dit_enabled(), "DIT not enabled");
#endif

    // To the cleanup function, indicate that we toggled DIT and
    // that cc_disable_dit() should actually disable it again.
    return true;
}

void cc_disable_dit(volatile bool *cc_unsafe_indexable dit_was_enabled);
#endif // CC_DIT_MAYBE_SUPPORTED


/* Here we declare all of our DIT macros */
#if CC_DIT_MAYBE_SUPPORTED
    #define CC_ENSURE_DIT_ENABLED                    \
        volatile bool _cc_dit_auto_disable           \
            __attribute__((cleanup(cc_disable_dit))) \
            __attribute__((unused)) = cc_enable_dit();
#else
    #define CC_ENSURE_DIT_ENABLED
#endif // CC_DIT_MAYBE_SUPPORTED

#if CC_DIT_WITH_SB_MAYBE_SUPPORTED
    #define CC_ENSURE_DIT_ENABLED_WITH_SB                    \
        volatile timingsafe_token_t _cc_dit_auto_diable      \
            __attribute__((cleanup(cc_disable_dit_with_sb))) \
            __attribute__((unused)) = cc_enable_dit_with_sb();
    
    #define CC_ASSERT_DIT_IS_ENABLED cc_test_ensure_dit_is_enabled();
#else
    // Fallback to `CC_DIT_MAYBE_SUPPORTED` version
    #define CC_ENSURE_DIT_ENABLED_WITH_SB CC_ENSURE_DIT_ENABLED
    #define CC_ASSERT_DIT_IS_ENABLED
#endif // CC_DIT_WITH_SB_MAYBE_SUPPORTED

#if CC_TEST_ASSERT_NO_NESTED_DITS
    #define CC_TEST_DISABLE_NESTED_DIT_CHECKS cc_test_disable_nested_dit_checks();
    #define CC_TEST_ENABLE_NESTED_DIT_CHECKS cc_test_enable_nested_dit_checks();
#else
    #define CC_TEST_DISABLE_NESTED_DIT_CHECKS
    #define CC_TEST_ENABLE_NESTED_DIT_CHECKS
#endif // CC_TEST_ASSERT_NO_NESTED_DITS

#if CC_TEST_ASSERT_DIT_ENABLED
    #define CC_TEST_DISABLE_DIT_ASSERTS cc_test_disable_dit_asserts();
    #define CC_TEST_ENABLE_DIT_ASSERTS cc_test_enable_dit_asserts();
    #define CC_TEST_WRAP_DISABLE_DIT_CHECKS(stmt) \
    ({ \
        CC_TEST_DISABLE_DIT_ASSERTS \
        stmt; \
        CC_TEST_ENABLE_DIT_ASSERTS \
    })

    #define CC_TEST_DISABLE_DIT_ASSERTS_WITH_RESTORE(dr) \
        int dr = cc_test_dit_asserts_enabled(); \
        CC_TEST_DISABLE_DIT_ASSERTS

    #define CC_TEST_RESTORE_DIT_ASSERTS(dr) \
        if (dr) { \
            CC_TEST_ENABLE_DIT_ASSERTS \
        }
#else
    #define CC_TEST_DISABLE_DIT_ASSERTS
    #define CC_TEST_ENABLE_DIT_ASSERTS
    #define CC_TEST_WRAP_DISABLE_DIT_CHECKS(stmt) stmt;
    #define CC_TEST_DISABLE_DIT_ASSERTS_WITH_RESTORE(dr)
    #define CC_TEST_RESTORE_DIT_ASSERTS(dr)
#endif // CC_TEST_ASSERT_DIT_ENABLED

/*!
  @function cc_is_vmm_present
  @abstract Determine if corecrypto is running in a VM

  @return True iff running in a VM; false otherwise

  @discussion This function merely checks the relevant sysctl, which
  may not be accurate. Thus, it should not be used to make any
  security decisions.
 */
extern bool cc_is_vmm_present(void);

/*!
  @function cc_current_arch
  @abstract The architecture loaded in the current process

  @return A string representation of the current architecture or
  "unknown"
 */
extern const char *cc_current_arch(void);

// MARK: - popcount

/// Count number of bits set
CC_INLINE CC_CONST unsigned cc_popcount32_fallback(uint32_t v)
{
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    return ((v + (v >> 4) & 0xf0f0f0f) * 0x1010101) >> 24;
}

/// Count number of bits set
CC_INLINE CC_CONST unsigned cc_popcount64_fallback(uint64_t v)
{
    v = v - ((v >> 1) & 0x5555555555555555);
    v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);
    v = (v + (v >> 4)) & 0xf0f0f0f0f0f0f0f;
    return (v * 0x101010101010101) >> 56;
}

/// Count number of bits set
CC_INLINE CC_CONST unsigned cc_popcount32(uint32_t data)
{
#if __has_builtin(__builtin_popcount)
    return (unsigned)__builtin_popcount(data);
#else
    return cc_popcount32_fallback(data);
#endif
}

/// Count number of bits set
CC_INLINE CC_CONST unsigned cc_popcount64(uint64_t data)
{
#if __has_builtin(__builtin_popcountll)
    return (unsigned)__builtin_popcountll(data);
#else
    return cc_popcount64_fallback(data);
#endif
}

// Use with volatile variables only.
#define CC_MULTI_IF_AND(condition) \
    ((condition) && (condition) && (condition))

// MARK: - Byte Extraction
#ifdef _MSC_VER
#define cc_byte(x, n) ((unsigned char)((x) >> (8 * (n))))
#else
#define cc_byte(x, n) (((x) >> (8 * (n))) & 255)
#endif

// MARK: - 32-bit Rotates

#if defined(_MSC_VER)
// MARK: -- MSVC version

#include <stdlib.h>
#if !defined(__clang__)
 #pragma intrinsic(_lrotr,_lrotl)
#endif
#define    CC_ROR(x,n) _lrotr(x,n)
#define    CC_ROL(x,n) _lrotl(x,n)
#define    CC_RORc(x,n) _lrotr(x,n)
#define    CC_ROLc(x,n) _lrotl(x,n)

#elif (defined(__i386__) || defined(__x86_64__))
// MARK: -- intel asm version

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    __asm__ ("roll %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
{
    __asm__ ("rorl %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROLc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("roll %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})


#define CC_RORc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("rorl %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})

#else

// MARK: -- default version

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    return ( (word<<(i&31)) | (word >> ( (32-(i&31)) & 31 )) );
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
{
    return ( (word>>(i&31)) | (word << ( (32-(i&31)) & 31 )) );
}

#define    CC_ROLc(x, y) CC_ROL(x, y)
#define    CC_RORc(x, y) CC_ROR(x, y)

#endif

// MARK: - 64 bits rotates

#if defined(__x86_64__) && !defined(_MSC_VER) //clang _MSVC doesn't support GNU-style inline assembly
// MARK: -- intel 64 asm version

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    __asm__("rolq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
{
    __asm__("rorq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROL64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rolq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})

#define CC_ROR64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rorq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})


#else /* Not x86_64  */

// MARK: -- default C version

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    return ( (word<<(i&63)) | (word >> ((64-(i&63)) & 63) ) );
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
{
    return ( (word>>(i&63)) | (word << ((64-(i&63)) & 63) ) );
}

#define    CC_ROL64c(x, y) CC_ROL64(x, y)
#define    CC_ROR64c(x, y) CC_ROR64(x, y)

#endif

// MARK: -- Count Leading / Trailing Zeros
/* Count leading zeros (for nonzero inputs) */

/*
 *  On i386 and x86_64, we know clang and GCC will generate BSR for
 *  __builtin_clzl.  This instruction IS NOT constant time on all micro-
 *  architectures, but it *is* constant time on all micro-architectures that
 *  have been used by Apple, and we expect that to continue to be the case.
 *
 *  When building for x86_64h with clang, this produces LZCNT, which is exactly
 *  what we want.
 *
 *  On arm and arm64, we know that clang and GCC generate the constant-time CLZ
 *  instruction from __builtin_clzl( ).
 */

#if defined(_WIN32)
/* We use the Windows implementations below. */
#elif defined(__x86_64__) || defined(__i386__) || defined(__arm64__) || defined(__arm__)
/* We use a thought-to-be-good version of __builtin_clz. */
#elif defined __GNUC__
#warning Using __builtin_clz() on an unknown architecture; it may not be constant-time.
/* If you find yourself seeing this warning, file a radar for someone to
 * check whether or not __builtin_clz() generates a constant-time
 * implementation on the architecture you are targeting.  If it does, append
 * the name of that architecture to the list of "safe" architectures above.  */
#endif

CC_INLINE CC_CONST unsigned cc_clz32_fallback(uint32_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from LSB to MSB
    for (int i = 0; i < 32; i++) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "leading bits are zero" counter "b".
        b += cc_value_barrier_unsigned(bit ^ 1);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= ~cc_bit_to_mask_unsigned(bit);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_clz64_fallback(uint64_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from LSB to MSB
    for (int i = 0; i < 64; i++) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "leading bits are zero" counter.
        b += cc_value_barrier_unsigned(bit ^ 1);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= ~cc_bit_to_mask_unsigned(bit);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_ctz32_fallback(uint32_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from MSB to LSB
    for (int i = 31; i >= 0; i--) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "trailing zero bits" counter.
        b += cc_value_barrier_unsigned(bit ^ 1);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= ~cc_bit_to_mask_unsigned(bit);
    }
    return b;
}

CC_INLINE CC_CONST unsigned cc_ctz64_fallback(uint64_t data)
{
    unsigned int b = 0;
    unsigned int bit = 0;
    // Work from MSB to LSB
    for (int i = 63; i >= 0; i--) {
        bit = (data >> i) & 1;
        // If the bit is 0, update the "trailing zero bits" counter.
        b += cc_value_barrier_unsigned(bit ^ 1);
        /* If the bit is 0, (bit - 1) is 0xffff... therefore b is retained.
         * If the bit is 1, (bit - 1) is 0 therefore b is set to 0.
         */
        b &= ~cc_bit_to_mask_unsigned(bit);
    }
    return b;
}

/*!
  @function cc_clz32
  @abstract Count leading zeros of a nonzero 32-bit value

  @param data A nonzero 32-bit value

  @result Count of leading zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_clz32(uint32_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_clz)
    cc_static_assert(sizeof(unsigned) == 4, "clz relies on an unsigned int being 4 bytes");
    return (unsigned)__builtin_clz(data);
#else
    return cc_clz32_fallback(data);
#endif
}

/*!
  @function cc_clz64
  @abstract Count leading zeros of a nonzero 64-bit value

  @param data A nonzero 64-bit value

  @result Count of leading zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_clz64(uint64_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_clzll)
    return (unsigned)__builtin_clzll(data);
#else
    return cc_clz64_fallback(data);
#endif
}

/*!
  @function cc_ctz32
  @abstract Count trailing zeros of a nonzero 32-bit value

  @param data A nonzero 32-bit value

  @result Count of trailing zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_ctz32(uint32_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_ctz)
    cc_static_assert(sizeof(unsigned) == 4, "ctz relies on an unsigned int being 4 bytes");
    return (unsigned)__builtin_ctz(data);
#else
    return cc_ctz32_fallback(data);
#endif
}

/*!
  @function cc_ctz64
  @abstract Count trailing zeros of a nonzero 64-bit value

  @param data A nonzero 64-bit value

  @result Count of trailing zeros of @p data

  @discussion @p data is assumed to be nonzero.
*/
CC_INLINE CC_CONST unsigned cc_ctz64(uint64_t data) {
    cc_assert(data != 0);
#if __has_builtin(__builtin_ctzll)
    return (unsigned)__builtin_ctzll(data);
#else
    return cc_ctz64_fallback(data);
#endif
}

// MARK: -- Find first bit set

/*!
  @function cc_ffs32_fallback
  @abstract Find first bit set in a 32-bit value

  @param data A 32-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs32_fallback(int32_t data)
{
    unsigned b = 0;
    unsigned bit = 0;
    unsigned seen = 0;

    // Work from LSB to MSB
    for (int i = 0; i < 32; i++) {
        bit = ((uint32_t)data >> i) & 1;

        // Track whether we've seen a 1 bit.
        seen |= cc_value_barrier_unsigned(bit);

        // If the bit is 0 and we haven't seen a 1 yet, increment b.
        b += cc_value_barrier_unsigned(bit ^ 1) & ~cc_bit_to_mask_unsigned(seen);
    }

    // If we saw a 1, return b + 1, else 0.
    return cc_bit_to_mask_unsigned(seen) & (b + 1);
}

/*!
  @function cc_ffs64_fallback
  @abstract Find first bit set in a 64-bit value

  @param data A 64-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs64_fallback(int64_t data)
{
    unsigned b = 0;
    unsigned bit = 0;
    unsigned seen = 0;

    // Work from LSB to MSB
    for (int i = 0; i < 64; i++) {
        bit = ((uint64_t)data >> i) & 1;

        // Track whether we've seen a 1 bit.
        seen |= cc_value_barrier_unsigned(bit);

        // If the bit is 0 and we haven't seen a 1 yet, increment b.
        b += cc_value_barrier_unsigned(bit ^ 1) & ~cc_bit_to_mask_unsigned(seen);
    }

    // If we saw a 1, return b + 1, else 0.
    return cc_bit_to_mask_unsigned(seen) & (b + 1);
}

/*!
  @function cc_ffs32
  @abstract Find first bit set in a 32-bit value

  @param data A 32-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs32(int32_t data)
{
    cc_static_assert(sizeof(int) == 4, "ffs relies on an int being 4 bytes");
#if __has_builtin(__builtin_ffs)
    return (unsigned)__builtin_ffs(data);
#else
    return cc_ffs32_fallback(data);
#endif
}

/*!
  @function cc_ffs64
  @abstract Find first bit set in a 64-bit value

  @param data A 64-bit value

  @result One plus the index of the least-significant bit set in @p data or, if @p data is zero, zero
 */
CC_INLINE CC_CONST unsigned cc_ffs64(int64_t data)
{
#if __has_builtin(__builtin_ffsll)
    return (unsigned)__builtin_ffsll(data);
#else
    return cc_ffs64_fallback(data);
#endif
}

// MARK: -- Overflow wrappers
#define cc_add_overflow __builtin_add_overflow

// On 32-bit architectures, clang emits libcalls to __mulodi4 when
// __builtin_mul_overflow() encounters `long long` types.
//
// The libgcc runtime does not provide __mulodi4, so for Linux on ARMv7
// we cannot call __builtin_mul_overflow().
//
// Using __has_builtin(__builtin_mul_overflow) would be better but that will
// return the correct response for ARMv7/Linux only with LLVM-14 or higher.
#if defined(__clang__) && defined(__arm__) && CC_LINUX
CC_INLINE bool cc_mul_overflow(uint64_t a, uint64_t b, uint64_t *r)
{
    *r = a * b;
    return (a != 0) && ((*r / a) != b);
}
#else
#define cc_mul_overflow __builtin_mul_overflow
#endif

// Set r := a if (m == -1). Set r := b if (m == 0).
//
// NOTE: Don't compute the mask yourself, use one of the helper functions
//       defined in cc_value_barrier.h. This ensures the compiler won't
//       replace the const-time conditional move with a branch instruction.
#define cc_mux_mask(r, m, a, b) do { \
    r = ((a) & (m)) | ((b) & ~(m));  \
} while (0);

CC_INLINE CC_WARN_RESULT
size_t cc_min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

CC_NONNULL((2, 3))
int cc_cmp_safe_internal(size_t num, const void * cc_sized_by(num) ptr1, const void * cc_sized_by(num) ptr2);

#endif // _CORECRYPTO_CC_INTERNAL_H_
