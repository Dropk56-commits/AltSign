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

#include "cc_internal.h"
#include <corecrypto/ccckg.h>
#include "ccckg_internal.h"

#include "ccansikdf_internal.h"
#include "ccec_internal.h"

ccec_const_cp_t ccckg_ctx_cp(ccckg_ctx_t ctx)
{
    return ctx->cp;
}

const struct ccdigest_info* ccckg_ctx_di(ccckg_ctx_t ctx)
{
    return ctx->di;
}

size_t ccckg_sizeof_ctx(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // Contributor stores scalar s and nonce r.
    // Owner stores scalar s, nonce r, and the commitment.
    return sizeof(struct ccckg_ctx) + ccec_ccn_size(cp) + ccn_sizeof_size(di->output_size) * 2;
}

size_t ccckg_sizeof_commitment(CC_UNUSED ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    return di->output_size;
}

size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // An EC point plus a nonce.
    return ccec_export_pub_size_cp(cp) + di->output_size;
}

size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // A scalar plus a nonce.
    return ccec_cp_order_size(cp) + di->output_size;
}

int ccckg_init(ccckg_ctx_t ctx, ccec_const_cp_t cp, const struct ccdigest_info *di, struct ccrng_state *rng)
{
    cc_clear(ccckg_sizeof_ctx(cp, di), ctx);

    ccckg_ctx_version(ctx) = CCCKG_VERSION_1;

    ctx->cp = cp;
    ctx->di = di;

    ccckg_ctx_rng(ctx) = rng;
    ccckg_ctx_state(ctx) = CCCKG_STATE_INIT;

    return CCERR_OK;
}

int ccckg_derive_sk(ccckg_ctx_t ctx, const cc_unit *x, const uint8_t *r1, const uint8_t *r2, size_t key_nbytes, uint8_t *key)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    uint8_t xbuf[CCCKG_CURVE_MAX_NBYTES];
    (void)ccn_write_uint_padded_internal(n, x, ccec_cp_prime_size(cp), xbuf);

    const cc_iovec_t shared_data[2] = {
        {
            .base = r1,
            .nbytes = di->output_size,
        },
        {
            .base = r2,
            .nbytes = di->output_size,
        },
    };

    return ccansikdf_x963_iovec(di, ccec_cp_prime_size(cp), xbuf, CC_ARRAY_LEN(shared_data), shared_data, key_nbytes, key);
}
