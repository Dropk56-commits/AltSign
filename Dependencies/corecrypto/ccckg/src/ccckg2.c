/* Copyright (c) (2023,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccansikdf.h>
#include "ccckg2_internal.h"
#include "ccec_internal.h"
#include "ccansikdf_internal.h"

static struct ccckg2_params _ccckg2_params_p224_sha256_v2 = {
    .version = CCCKG_VERSION_2,
    .cp = ccec_cp_224,
    .di = ccsha256_di
};

ccckg2_params_t ccckg2_params_p224_sha256_v2(void)
{
    return &_ccckg2_params_p224_sha256_v2;
}

ccec_const_cp_t ccckg2_ctx_cp(ccckg2_ctx_t ctx)
{
    return ctx->cp;
}

const struct ccdigest_info* ccckg2_ctx_di(ccckg2_ctx_t ctx)
{
    return ctx->di;
}

size_t ccckg2_sizeof_ctx(ccckg2_params_t params)
{
    cc_assert(params->version == CCCKG_VERSION_2);

    ccec_const_cp_t cp = params->cp();
    const struct ccdigest_info *di = params->di();

    // Contributor stores scalar s, scalar r, and point R.
    size_t nc = ccec_ccn_size(cp) * 2 + 1 + 2 * ccec_cp_prime_size(cp);

    // Owner stores scalar s, scalar r, and the commitment.
    size_t no = ccec_ccn_size(cp) * 2 + ccn_sizeof_size(di->output_size);

    return sizeof(struct ccckg2_ctx) + CC_MAX_EVAL(nc, no);
}

size_t ccckg2_sizeof_commitment(ccckg2_params_t params)
{
    cc_assert(params->version == CCCKG_VERSION_2);

    return ccckg2_sizeof_commitment_internal(params->di());
}

size_t ccckg2_sizeof_share(ccckg2_params_t params)
{
    cc_assert(params->version == CCCKG_VERSION_2);

    return ccckg2_sizeof_share_internal(params->cp());
}

size_t ccckg2_sizeof_opening(ccckg2_params_t params)
{
    cc_assert(params->version == CCCKG_VERSION_2);

    return ccckg2_sizeof_opening_internal(params->cp());
}

int ccckg2_init(ccckg2_ctx_t ctx, ccckg2_params_t params)
{
    if (params->version != CCCKG_VERSION_2) {
        return CCERR_PARAMETER;
    }

    cc_clear(ccckg2_sizeof_ctx(params), ctx);

    ccckg_ctx_version(ctx) = params->version;

    ctx->cp = params->cp();
    ctx->di = params->di();

    ccckg_ctx_state(ctx) = CCCKG_STATE_INIT;

    return CCERR_OK;
}

int ccckg2_derive_sk_ws(cc_ws_t ws,
                        ccckg2_ctx_t ctx,
                        const uint8_t *R_bytes,
                        ccec_pub_ctx_t P,
                        size_t sk_nbytes,
                        uint8_t *sk,
                        struct ccrng_state *rng)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    const struct ccdigest_info *di = ccckg2_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    if (R_bytes[0] != 0x04) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *X = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Y = CCEC_ALLOC_POINT_WS(ws, n);

    ccec_pub_ctx_t R = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, R);

    // Import R' and compute RR = r * R'.
    int rv = ccec_raw_import_pub(cp, ccec_export_pub_size(R) - 1, R_bytes + 1, R);
    cc_require(rv == CCERR_OK, cleanup);

    rv = ccec_validate_point_and_projectify_ws(ws, cp, X, (ccec_const_affine_point_t)ccec_ctx_point(R), rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Y = r * R'
    rv = ccec_mult_blinded_ws(ws, cp, Y, ccckg2_ctx_r(ctx), X, rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Affinify Y.
    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(R), Y);
    cc_require(rv == CCERR_OK, cleanup);

    // Derive SK = KDF(x(P), RR = r * R' = r' * R).
    uint8_t xbuf[CCCKG_CURVE_MAX_NBYTES];
    (void)ccn_write_uint_padded_internal(n, ccec_ctx_x(P), ccec_cp_prime_size(cp), xbuf);

    uint8_t rbuf[1 + CCCKG_CURVE_MAX_NBYTES * 2];
    rv = ccec_export_pub(R, rbuf);
    cc_require(rv == CCERR_OK, cleanup);
    
    // We'll use ccansikdf_x963_iovec to sidestep the DIT call in ccansikdf_x963
    
    const cc_iovec_t shared_data[1] = {
        {
            .base = rbuf,
            .nbytes = ccec_export_pub_size_cp(cp),
        },
    };

    rv = ccansikdf_x963_iovec(di, ccec_cp_prime_size(cp), xbuf, 1, shared_data, sk_nbytes, sk);
    cc_require(rv == CCERR_OK, cleanup);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg2_derive_sk(ccckg2_ctx_t ctx,
                     const uint8_t *R_bytes,
                     ccec_pub_ctx_t P,
                     size_t sk_nbytes,
                     uint8_t *sk,
                     struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG2_DERIVE_SK_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg2_derive_sk_ws(ws, ctx, R_bytes, P, sk_nbytes, sk, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
