/* Copyright (c) (2012,2015,2020,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"

bool ccdh_valid_shared_secret(cc_size n, const cc_unit *s, ccdh_const_gp_t gp)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    cc_assert(ccdh_gp_prime(gp)[0] & 1);

    if (ccn_is_zero_or_one(n, s)) {
        return false;
    }

    // Both (a=-1 and b=-1) iff (s == p - 1).
    cc_unit a = cc_eq_mask_cc_units(n - 1, s + 1, ccdh_gp_prime(gp) + 1);
    cc_unit b = cc_eq_mask_cc_unit(s[0], ccdh_gp_prime(gp)[0] - 1);

    return ~(a & b);
}
