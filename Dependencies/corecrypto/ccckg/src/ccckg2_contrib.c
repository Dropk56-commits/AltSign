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

#include "ccckg2_internal.h"
#include "ccec_internal.h"
#include "ccdigest_internal.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int ccckg2_contributor_commit_ws(cc_ws_t ws,
                                        ccckg2_ctx_t ctx,
                                        size_t commitment_nbytes,
                                        uint8_t *commitment,
                                        struct ccrng_state *rng)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    const struct ccdigest_info *di = ccckg2_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccdigest_di_decl(di, dc);

    CCCKG_EXPECT_STATE(INIT);

    if (ccckg_ctx_version(ctx) != CCCKG_VERSION_2) {
        return CCERR_PARAMETER;
    }

    if (commitment_nbytes != ccckg2_sizeof_commitment_internal(di)) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    ccec_full_ctx_t R = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, R);

    // Generate a scalar s and store it.
    int rv = ccec_generate_scalar_fips_retry_ws(ws, cp, rng, ccckg2_ctx_s(ctx));
    cc_require(rv == CCERR_OK, cleanup);

    // Generate a scalar r and compute point R.
    rv = ccec_generate_key_fips_ws(ws, cp, rng, R);
    cc_require(rv == CCERR_OK, cleanup);

    // Store scalar r.
    ccn_set(n, ccckg2_ctx_r(ctx), ccec_ctx_k(R));

    // Store encoding of point R = r * G.
    rv = ccec_export_pub(ccec_ctx_pub(R), ccckg2_ctx_rG(ctx));
    cc_require(rv == CCERR_OK, cleanup);

    // Write the commitment.
    uint8_t buf[CCCKG_CURVE_MAX_NBYTES];
    ccn_write_uint_padded_internal(n, ccckg2_ctx_s(ctx), ccec_cp_order_size(cp), buf);

    ccdigest_init_internal(di, dc);
    ccdigest_update_internal(di, dc, ccec_cp_order_size(cp), buf);
    ccdigest_update_internal(di, dc, ccec_export_pub_size(ccec_ctx_pub(R)), ccckg2_ctx_rG(ctx));
    ccdigest_final(di, dc, commitment);
    ccdigest_di_clear(di, dc);

    CCCKG_SET_STATE(COMMIT);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg2_contributor_commit(ccckg2_ctx_t ctx,
                              size_t commitment_nbytes,
                              uint8_t *commitment,
                              struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG2_CONTRIBUTOR_COMMIT_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg2_contributor_commit_ws(ws, ctx, commitment_nbytes, commitment, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccckg2_contributor_finish_ws(cc_ws_t ws,
                                        ccckg2_ctx_t ctx,
                                        size_t share_nbytes,
                                        const uint8_t *share,
                                        size_t opening_nbytes,
                                        uint8_t *opening,
                                        ccec_pub_ctx_t P,
                                        size_t sk_nbytes,
                                        uint8_t *sk,
                                        struct ccrng_state *rng)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    int rv;

    CCCKG_EXPECT_STATE(COMMIT);

    if (ccckg_ctx_version(ctx) != CCCKG_VERSION_2) {
        return CCERR_PARAMETER;
    }

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (share_nbytes != ccckg2_sizeof_share_internal(cp)) {
        return CCERR_PARAMETER;
    }

    if (opening_nbytes != ccckg2_sizeof_opening_internal(cp)) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    // Derive P = S' + s * G.
    rv = ccckg_contributor_finish_derive_p_ws(ws, (ccckg_ctx_t)ctx, share, P, rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Derive SK = KDF(x(P), RR = r * R').
    rv = ccckg2_derive_sk_ws(ws, ctx, share + ccec_export_pub_size_cp(cp), P, sk_nbytes, sk, rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Open the commitment.
    ccn_write_uint_padded_internal(n, ccckg2_ctx_s(ctx), ccec_cp_order_size(cp), opening);
    cc_memcpy(opening + ccec_cp_order_size(cp), ccckg2_ctx_rG(ctx), ccec_export_pub_size_cp(cp));

    CCCKG_SET_STATE(FINISH);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg2_contributor_finish(ccckg2_ctx_t ctx,
                              size_t share_nbytes,
                              const uint8_t *share,
                              size_t opening_nbytes,
                              uint8_t *opening,
                              ccec_pub_ctx_t P,
                              size_t sk_nbytes,
                              uint8_t *sk,
                              struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG2_CONTRIBUTOR_FINISH_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg2_contributor_finish_ws(ws, ctx, share_nbytes, share, opening_nbytes, opening, P, sk_nbytes, sk, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
