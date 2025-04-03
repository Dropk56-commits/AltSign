/* Copyright (c) (2014,2015,2019,2021,2024,2025) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"

int cc_cmp_safe_internal(size_t num, const void *ptr1, const void *ptr2)
{
    CC_ASSERT_DIT_IS_ENABLED

    if (num == 0) {
        return 1;
    }

    const uint8_t *s = (const uint8_t *)ptr1;
    const uint8_t *t = (const uint8_t *)ptr2;

    uint8_t flag = 0;
    // Loop computation is reversed as a defense against a speculative early exit of the loop
    // by forcing the processor to retrieve num from cache, reducing the speculation window.
    for (size_t i = num; i > 0; i -= 1) {
        flag |= cc_value_barrier_uint8(s[i-1] ^ t[i-1]);
    }

    CC_TEST_DISABLE_NESTED_DIT_CHECKS
    CC_ENSURE_DIT_ENABLED_WITH_SB // This calls timingsafe_enable_if_supported(), which adds a speculation barrier
    CC_TEST_ENABLE_NESTED_DIT_CHECKS

    // 0 iff all bytes were equal, 1 if there is any difference
    return cc_nonzero_mask_uint8(flag) & 1;
}


int cc_cmp_safe(size_t num, const void *ptr1, const void *ptr2)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return cc_cmp_safe_internal(num, ptr1, ptr2);
}
