/* Copyright (c) (2016,2019-2021,2024) Apple Inc. All rights reserved.
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

static int ccrsa_make_pub_ws(cc_ws_t ws,
                             ccrsa_pub_ctx_t pubk,
                             size_t exp_nbytes, const uint8_t *exp,
                             size_t mod_nbytes, const uint8_t *mod)
{
    cc_size n = ccrsa_ctx_n(pubk);

    if (ccn_read_uint_public_value(n, ccrsa_ctx_m(pubk), mod_nbytes, mod)) {
        return CCRSA_INVALID_INPUT;
    }

    if (ccn_read_uint_public_value(n, ccrsa_ctx_e(pubk), exp_nbytes, exp)) {
        return CCRSA_INVALID_INPUT;
    }

    return cczp_mm_init_ws(ws, ccrsa_ctx_zm(pubk), n, NULL);
}

int ccrsa_make_pub(ccrsa_pub_ctx_t pubk,
                   size_t exp_nbytes, const uint8_t *exp,
                   size_t mod_nbytes, const uint8_t *mod)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_MAKE_PUB_WORKSPACE_N(ccrsa_ctx_n(pubk)));
    int rv = ccrsa_make_pub_ws(ws, pubk, exp_nbytes, exp, mod_nbytes, mod);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
