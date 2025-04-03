/* Copyright (c) (2010,2011,2014-2017,2019,2021,2024) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

int ccrsa_pub_crypt_ws(cc_ws_t ws, ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    cc_size n = ccrsa_ctx_n(ctx);
    cczp_t zm = ccrsa_ctx_zm(ctx);

    size_t ebitlen = ccn_bitlen_internal(n, ccrsa_ctx_e(ctx));

    // Reject e<=1 and m<=1 as a valid key.
    if ((ebitlen <= 1) || ccn_is_zero_or_one(n, ccrsa_ctx_m(ctx))) {
        return CCRSA_KEY_ERROR;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);

    cczp_to_ws(ws, zm, t0, s);
    int rv = cczp_power_fast_ws(ws, zm, t1, t0, ccrsa_ctx_e(ctx));
    cczp_from_ws(ws, zm, r, t1);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccrsa_pub_crypt(ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_PUB_CRYPT_WORKSPACE_N(ccrsa_ctx_n(ctx)));
    int rv = ccrsa_pub_crypt_ws(ws, ctx, r, s);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
