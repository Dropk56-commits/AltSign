/* Copyright (c) (2020,2021,2024) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"

int cczp_is_quadratic_residue_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *a)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    // pm1 = p-1
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, pm1, cczp_prime(zp));
    pm1[0] &= ~CC_UNIT_C(1);

    // pm1h = (p-1)/2
    cc_unit *pm1h = CC_ALLOC_WS(ws, n);
    ccn_shift_right(n, pm1h, pm1, 1);

    // s = a^((p-1)/2)
    cc_unit *s = CC_ALLOC_WS(ws, n);

    // cczp_power_fast_ws() fails for a >= p.
    int rv1 = cczp_power_fast_ws(ws, zp, s, a, pm1h);
    rv1 = cc_nonzero_mask_int(rv1);

    // a^((p-1)/2) =  1 mod p, if a is a quadratic residue.
    // a^((p-1)/2) = -1 mod p, if a is a non-residue. This is a failure case.
    // a^((p-1)/2) =  0 mod p, if gcd(a,p) > 1. This is a failure case.
    cczp_from_ws(ws, zp, s, s);

    // rv2 = (s == 1) ? 0 : -1
    cc_unit ns = (cc_unit)ccn_n(n, s);
    cc_unit is_one = cc_eq_mask_cc_unit(ns | s[0], 1);
    int rv2 = ~cc_bit_to_mask_int(is_one & 1);

    CC_FREE_BP_WS(ws, bp);
    return rv1 | rv2;
}
