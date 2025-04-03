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

#include <corecrypto/cczp_priv.h>
#include "ccckg2_internal.h"
#include "ccec_internal.h"
#include "ccdigest_internal.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int ccckg2_owner_generate_share_ws(cc_ws_t ws,
                                          ccckg2_ctx_t ctx,
                                          size_t commitment_nbytes,
                                          const uint8_t *commitment,
                                          size_t share_nbytes,
                                          uint8_t *share,
                                          struct ccrng_state *rng)
{
    const struct ccdigest_info *di = ccckg2_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    CCCKG_EXPECT_STATE(INIT);

    if (commitment_nbytes != ccckg2_sizeof_commitment_internal(di)) {
        return CCERR_PARAMETER;
    }

    if (share_nbytes != ccckg2_sizeof_share_internal(cp)) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    ccec_full_ctx_t S = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, S);

    ccec_full_ctx_t R = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, R);

    // Store the contributor's commitment.
    cc_memcpy(ccckg2_ctx_c(ctx), commitment, commitment_nbytes);

    // Generate a new key share.
    int rv = ccec_generate_key_fips_ws(ws, cp, rng, S);
    cc_require(rv == CCERR_OK, cleanup);

    // Store scalar s.
    ccn_set(n, ccckg2_ctx_s(ctx), ccec_ctx_k(S));

    // Generate another key share.
    rv = ccec_generate_key_fips_ws(ws, cp, rng, R);
    cc_require(rv == CCERR_OK, cleanup);

    // Store scalar r.
    ccn_set(n, ccckg2_ctx_r(ctx), ccec_ctx_k(R));

    // Encode C2 = S' || R'.
    rv = ccec_export_pub(ccec_ctx_pub(S), share);
    cc_require(rv == CCERR_OK, cleanup);

    rv = ccec_export_pub(ccec_ctx_pub(R), share + ccec_export_pub_size_cp(cp));
    cc_require(rv == CCERR_OK, cleanup);

    CCCKG_SET_STATE(SHARE);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg2_owner_generate_share(ccckg2_ctx_t ctx,
                                size_t commitment_nbytes,
                                const uint8_t *commitment,
                                size_t share_nbytes,
                                uint8_t *share,
                                struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG2_OWNER_GENERATE_SHARE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg2_owner_generate_share_ws(ws, ctx, commitment_nbytes, commitment, share_nbytes, share, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccckg2_owner_finish(ccckg2_ctx_t ctx,
                        size_t opening_nbytes,
                        const uint8_t *opening,
                        ccec_full_ctx_t P,
                        size_t sk_nbytes,
                        uint8_t *sk,
                        struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    const struct ccdigest_info *di = ccckg2_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);

    CCCKG_EXPECT_STATE(SHARE);

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (opening_nbytes != ccckg2_sizeof_opening_internal(cp)) {
        return CCERR_PARAMETER;
    }

    uint8_t buf[CCCKG_HASH_MAX_NBYTES];
    ccdigest_internal(di, opening_nbytes, opening, buf);

    int rv = CCERR_INTEGRITY;

    // Check the commitment.
    if (cc_cmp_safe_internal(di->output_size, buf, ccckg2_ctx_c(ctx))) {
        goto cleanup;
    }

    // Compute P = (s + s') * G.
    rv = ccckg_owner_finish_derive_p((ccckg_ctx_t)ctx, opening, P, rng);
    cc_require(rv == CCERR_OK, cleanup);

    // Derive SK = KDF(x(P), RR = r' * R).
    rv = ccckg2_derive_sk(ctx, opening + ccec_cp_order_size(cp), ccec_ctx_pub(P), sk_nbytes, sk, rng);
    cc_require(rv == CCERR_OK, cleanup);

    CCCKG_SET_STATE(FINISH);

cleanup:
    cc_clear(sizeof(buf), buf);
    return rv;
}
