/* Copyright (c) (2010,2011,2015,2016,2018,2019,2021,2024) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

size_t ccn_bitlen_public_value(cc_size count, const cc_unit *s)
{
    size_t bl = 0;

    for (cc_size i = 0; i < count; i++) {
        // Update bl only if s[i] > 0. We need to OR s[i] with 1 to
        // avoid the invalid cc_clz_nonzero(0) case.
        cc_size clz = cc_clz_nonzero(s[i] | 1);
        cc_unit m = cc_nonzero_mask_cc_unit(s[i]);
        cc_mux_mask(bl, m, ccn_bitsof_n(i + 1) - clz, bl);
    }

    return bl;
}

size_t ccn_bitlen_internal(cc_size count, const cc_unit *s)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    return ccn_bitlen_public_value(count, s);
}

size_t ccn_bitlen(cc_size count, const cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccn_bitlen_internal(count, s);
}
