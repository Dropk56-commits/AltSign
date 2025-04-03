/* Copyright (c) (2010,2015,2016,2019,2021,2022,2024,2025) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>
#include "ccn_internal.h"

#if CCN_CMP_ASM
int ccn_cmp_asm(cc_size n, const cc_unit *s, const cc_unit *t) __asm__("_ccn_cmp_asm");
#endif

CC_UNUSED CC_WARN_RESULT CC_NONNULL_ALL
static int ccn_cmp_noasm(cc_size n, const cc_unit *s, const cc_unit *t)
{
    cc_unit six = 0;
    cc_unit tix = 0;

    // Loop computation is reversed as a defense against a speculative early exit of the loop
    // by forcing the processor to retrieve `n` from cache, reducing the speculation window.
    for (cc_size ix = n; ix > 0; ix--) {
        cc_unit m = cc_eq_mask_cc_unit(s[n-ix], t[n-ix]);
        cc_mux_mask(six, m, six, s[n-ix]);
        cc_mux_mask(tix, m, tix, t[n-ix]);
    }

    cc_unit m1 = ~cc_eq_mask_cc_unit(six, tix);     //  0 if (=), -1 otherwise
    cc_unit m2 = cc_smaller_mask_cc_unit(six, tix); // -1 if (-),  0 otherwise

    int d1 = cc_nonzero_mask_int((int)m1);
    int d2 = cc_nonzero_mask_int((int)m2);

    CC_TEST_DISABLE_NESTED_DIT_CHECKS
    CC_ENSURE_DIT_ENABLED_WITH_SB // This calls timingsafe_enable_if_supported(), which adds a speculation barrier
    CC_TEST_ENABLE_NESTED_DIT_CHECKS

    // If d1= 0,          return  0: s = t
    // If d1=-1 && d2= 0, return  1: s > t
    // If d1=-1 && d2=-1, return -1: s < t
    return d1 & (d2 + (~d2 & 1));
}

int ccn_cmp_public_value(cc_size n, const cc_unit *s, const cc_unit *t)
{
    int cmp = 0;
    
#if CCN_CMP_ASM
    cmp = ccn_cmp_asm(n, s, t);
#else
    cmp = ccn_cmp_noasm(n, s, t);
#endif /* CCN_CMP_ASM */

    cc_assert(cmp == ccn_cmp_noasm(n, s, t));

    return cmp;
}

int ccn_cmp_internal(cc_size n, const cc_unit *s, const cc_unit *t)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    return ccn_cmp_public_value(n, s, t);
}

// constant time comparison when assembly is not available
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccn_cmp_internal(n, s, t);
}
