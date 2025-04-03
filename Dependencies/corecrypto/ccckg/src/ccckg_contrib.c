/* Copyright (c) (2019-2024) Apple Inc. All rights reserved.
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

#include "ccec_internal.h"
#include "ccckg_internal.h"
#include "ccdigest_internal.h"

int ccckg_contributor_commit(ccckg_ctx_t ctx, size_t commitment_nbytes, uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    cczp_const_t zq = ccec_cp_zq(cp);

    ccdigest_di_decl(di, dc);
    int rv;

    CCCKG_EXPECT_STATE(INIT);
    
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_SCALAR_FIPS_RETRY_WORKSPACE_N(cczp_n(zq)));
    if (commitment_nbytes != ccckg_sizeof_commitment(cp, di)) {
        rv = CCERR_PARAMETER;
        goto cleanup;
    }

    // Generate a new scalar and store it.
    if ((rv = ccec_generate_scalar_fips_retry_ws(ws, cp, ccckg_ctx_rng(ctx), ccckg_ctx_s(ctx)))) {
        goto cleanup;
    }

    // Generate a nonce r.
    if ((rv = ccrng_generate(ccckg_ctx_rng(ctx), di->output_size, ccckg_ctx_r(ctx)))) {
        goto cleanup;
    }

    // Write the commitment.
    uint8_t buf[CCCKG_CURVE_MAX_NBYTES];
    ccn_write_uint_padded_internal(n, ccckg_ctx_s(ctx), ccec_cp_order_size(cp), buf);

    ccdigest_init_internal(di, dc);
    ccdigest_update_internal(di, dc, ccec_cp_order_size(cp), buf);
    ccdigest_update_internal(di, dc, di->output_size, ccckg_ctx_r(ctx));
    ccdigest_final(di, dc, commitment);
    ccdigest_di_clear(di, dc);

    CCCKG_SET_STATE(COMMIT);

cleanup:
    CC_FREE_WORKSPACE(ws);
    cc_clear(sizeof(buf), buf);

    return rv;
}

int ccckg_contributor_finish_derive_p_ws(cc_ws_t ws,
                                         ccckg_ctx_t ctx,
                                         const uint8_t *S_bytes,
                                         ccec_pub_ctx_t P,
                                         struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    if (S_bytes[0] != 0x04) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *X = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Y = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *G = CCEC_ALLOC_POINT_WS(ws, n);

    ccec_pub_ctx_t S = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, S);

    // Import S'.
    int rv = ccec_raw_import_pub(cp, ccec_export_pub_size(S) - 1, S_bytes + 1, S);
    cc_require(rv == CCERR_OK, cleanup);

    rv = ccec_validate_point_and_projectify_ws(ws, cp, X, (ccec_const_affine_point_t)ccec_ctx_point(S), rng);
    cc_require(rv == CCERR_OK, cleanup);

    rv = ccec_projectify_ws(ws, cp, G, ccec_cp_g(cp), rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Y = s * G
    rv = ccec_mult_blinded_ws(ws, cp, Y, ccckg_ctx_s(ctx), G, rng);
    cc_require(rv == CCERR_OK, cleanup);

    // P = X + Y = S' + s * G
    ccec_full_add_ws(ws, cp, ccec_ctx_point(P), X, Y);

    // Affinify P.
    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(P), ccec_ctx_point(P));
    cc_require(rv == CCERR_OK, cleanup);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccckg_contributor_finish_ws(cc_ws_t ws,
                                       ccckg_ctx_t ctx,
                                       size_t share_nbytes,
                                       const uint8_t *share,
                                       size_t opening_nbytes,
                                       uint8_t *opening,
                                       ccec_pub_ctx_t P,
                                       size_t sk_nbytes,
                                       uint8_t *sk)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    struct ccrng_state *rng = ccckg_ctx_rng(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    CCCKG_EXPECT_STATE(COMMIT);

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (share_nbytes != ccckg_sizeof_share(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (opening_nbytes != ccckg_sizeof_opening(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (share[0] != 0x04) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    // Derive P = S' + s * G.
    int rv = ccckg_contributor_finish_derive_p_ws(ws, ctx, share, P, rng);
    cc_require(rv == CCERR_OK, cleanup);

    const uint8_t *r1 = (const uint8_t *)ccckg_ctx_r(ctx);
    const uint8_t *r2 = (const uint8_t *)share + ccec_export_pub_size_cp(cp);

    // Derive SK.
    rv = ccckg_derive_sk(ctx, ccec_ctx_x(P), r1, r2, sk_nbytes, sk);
    cc_require(rv == CCERR_OK, cleanup);

    // Open the commitment.
    ccn_write_uint_padded_internal(n, ccckg_ctx_s(ctx), ccec_cp_order_size(cp), opening);
    cc_memcpy(opening + ccec_cp_order_size(cp), ccckg_ctx_r(ctx), di->output_size);

    CCCKG_SET_STATE(FINISH);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg_contributor_finish(ccckg_ctx_t ctx,
                             size_t share_nbytes,
                             const uint8_t *share,
                             size_t opening_nbytes,
                             uint8_t *opening,
                             ccec_pub_ctx_t P,
                             size_t sk_nbytes,
                             uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG_CONTRIBUTOR_FINISH_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg_contributor_finish_ws(ws, ctx, share_nbytes, share, opening_nbytes, opening, P, sk_nbytes, sk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
