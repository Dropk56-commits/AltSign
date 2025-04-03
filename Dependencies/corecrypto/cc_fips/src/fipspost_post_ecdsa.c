/* Copyright (c) (2017-2022,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_memory.h"
#include "cc_workspaces.h"
#include "ccrng_zero.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_ecdsa.h"

#define MAX_SIGNATURE_NBYTES (3 + 2 * (3 + CC_BITLEN_TO_BYTELEN(521)))
#define MAX_SIGNATURE_R_S_NBYTES CC_BITLEN_TO_BYTELEN(521)

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_sign_ws(cc_ws_t ws,
                                       uint32_t fips_mode,
                                       ccec_const_cp_t cp,
                                       const struct ccdigest_info *di,
                                       size_t msg_nbytes,
                                       uint8_t *msg_bytes,
                                       size_t dQ_nbytes,
                                       uint8_t *dQ_bytes,
                                       size_t k_nbytes,
                                       uint8_t *k_bytes,
                                       size_t r_nbytes,
                                       uint8_t *r_bytes,
                                       size_t s_nbytes,
                                       uint8_t *s_bytes)
{
    struct ccrng_ecfips_test_state ectest_rng;
    struct ccrng_state *rng = (struct ccrng_state *)&ectest_rng;

    size_t cp_bits = ccec_cp_prime_bitlen(cp);
    size_t di_bits = di->output_size * 8;

    CC_DECL_BP_WS(ws, bp);
    cc_size n = ccec_cp_n(cp);

    ccec_full_ctx_t key = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, key);

    CC_TEST_DISABLE_DIT_ASSERTS
    int ret = ccec_x963_import_priv_ws(ws, cp, dQ_nbytes, dQ_bytes, key);
    CC_TEST_ENABLE_DIT_ASSERTS
    if (ret != 0) {
        failf("failed ccec_x963_import_priv (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        ret = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        k_nbytes -= 1;
    }

    ccrng_ecfips_test_init(&ectest_rng, k_nbytes, k_bytes);

    uint8_t sig[MAX_SIGNATURE_NBYTES];
    size_t sig_len = sizeof(sig);

    CC_TEST_DISABLE_DIT_ASSERTS
    ret = ccec_sign_msg_ws(ws, key, di, msg_nbytes, msg_bytes, &sig_len, sig, rng);
    CC_TEST_ENABLE_DIT_ASSERTS
    if (ret != 0) {
        failf("failed ccec_sign_msg (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_GENERIC_FAILURE;
    }

    uint8_t r[MAX_SIGNATURE_R_S_NBYTES];
    uint8_t s[MAX_SIGNATURE_R_S_NBYTES];

    CC_TEST_DISABLE_DIT_ASSERTS
    ret = ccec_extract_rs_ws(ws, ccec_ctx_pub(key), sig_len, sig, r, s);
    CC_TEST_ENABLE_DIT_ASSERTS
    if (ret != 0) {
        failf("failed ccec_extract_rs (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        ret = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    if (memcmp(r, r_bytes, r_nbytes)) {
        failf("failed ECDSA_P%zu_SHA%zu KAT (r)", cp_bits, di_bits);
        ret = CCPOST_KAT_FAILURE;
        goto errOut;
    }

    if (memcmp(s, s_bytes, s_nbytes)) {
        failf("failed ECDSA_P%zu_SHA%zu KAT (s)", cp_bits, di_bits);
        ret = CCPOST_KAT_FAILURE;
        goto errOut;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}

const struct fipspost_ecdsa_sign_kat {
    ccec_const_cp_t (*cp)(void);
    const struct ccdigest_info *(*di)(void);
    size_t msg_len;
    uint8_t *msg;
    size_t dq_len;
    uint8_t *dq;
    size_t k_len;
    uint8_t *k;
    size_t r_len;
    uint8_t *r;
    size_t s_len;
    uint8_t *s;
} sign_kat_tvs[] = {
#include "../test_vectors/fipspost_post_ecdsa_sign.kat"
};

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_kat_sign_ws(cc_ws_t ws, uint32_t fips_mode)
{
    int ret = CCPOST_GENERIC_FAILURE;

    CC_DECL_BP_WS(ws, bp);

    for (size_t i = 0; i < CC_ARRAY_LEN(sign_kat_tvs); i++) {
        const struct fipspost_ecdsa_sign_kat *kat = &sign_kat_tvs[i];

        ccec_const_cp_t cp = kat->cp();
        const struct ccdigest_info *di = kat->di();

        size_t cp_bits = ccec_cp_prime_bitlen(cp);
        size_t di_bits = di->output_size * 8;

        CC_TEST_DISABLE_DIT_ASSERTS
        ret = fipspost_post_ecdsa_sign_ws(ws, fips_mode, cp, di,
                                          kat->msg_len, kat->msg,
                                          kat->dq_len, kat->dq,
                                          kat->k_len, kat->k,
                                          kat->r_len, kat->r,
                                          kat->s_len, kat->s);
        CC_TEST_ENABLE_DIT_ASSERTS
        if (ret != 0) {
            failf("failed ECDSA_P%zu_SHA%zu_SIG KAT #%zu", cp_bits, di_bits, i);
            ret = CCPOST_KAT_FAILURE;
            break;
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return ret;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_verify_ws(cc_ws_t ws,
                                         uint32_t fips_mode,
                                         ccec_const_cp_t cp,
                                         const struct ccdigest_info *di,
                                         size_t msg_nbytes,
                                         uint8_t *msg_bytes,
                                         size_t Q_nbytes,
                                         uint8_t *Q_bytes,
                                         size_t sig_nbytes,
                                         uint8_t *sig_bytes)
{
    size_t cp_bits = ccec_cp_prime_bitlen(cp);
    size_t di_bits = di->output_size * 8;

    CC_DECL_BP_WS(ws, bp);
    cc_size n = ccec_cp_n(cp);

    ccec_pub_ctx_t key = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, key);

    CC_TEST_DISABLE_DIT_ASSERTS
    int ret = ccec_x963_import_pub_ws(ws, cp, Q_nbytes, Q_bytes, key);
    if (ret != 0) {
        failf("failed ccec_x963_import_pub (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        ret = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    uint8_t sig[MAX_SIGNATURE_NBYTES];
    memcpy(sig, sig_bytes, sig_nbytes);
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        sig[0] ^= 0x5a;
    }

    ret = ccec_verify_msg_ws(ws, key, di, msg_nbytes, msg_bytes, sig_nbytes, sig, NULL);
    if (ret != 0) {
        failf("failed ccec_verify_msg (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        ret = CCPOST_KAT_FAILURE;
        goto errOut;
    }
    CC_TEST_ENABLE_DIT_ASSERTS

errOut:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}

const struct fipspost_ecdsa_verify_kat {
    ccec_const_cp_t (*cp)(void);
    const struct ccdigest_info *(*di)(void);
    size_t msg_len;
    uint8_t *msg;
    size_t q_len;
    uint8_t *q;
    size_t sig_len;
    uint8_t *sig;
} verify_kat_tvs[] = {
#include "../test_vectors/fipspost_post_ecdsa_verify.kat"
};

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_kat_verify_ws(cc_ws_t ws, uint32_t fips_mode)
{
    int ret = CCPOST_GENERIC_FAILURE;

    CC_DECL_BP_WS(ws, bp);

    for (size_t i = 0; i < CC_ARRAY_LEN(verify_kat_tvs); i++) {
        const struct fipspost_ecdsa_verify_kat *kat = &verify_kat_tvs[i];

        ccec_const_cp_t cp = kat->cp();
        const struct ccdigest_info *di = kat->di();

        size_t cp_bits = ccec_cp_prime_bitlen(cp);
        size_t di_bits = di->output_size * 8;

        ret = fipspost_post_ecdsa_verify_ws(ws, fips_mode, cp, di,
                                            kat->msg_len, kat->msg,
                                            kat->q_len, kat->q,
                                            kat->sig_len, kat->sig);
        if (ret != 0) {
            failf("failed ECDSA_P%zu_SHA%zu_VER KAT #%zu", cp_bits, di_bits, i);
            ret = CCPOST_KAT_FAILURE;
            break;
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return ret;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_pairwise_ws(cc_ws_t ws)
{
    // This test is not a true POST test, but meets a requirement from FIPS to ensure that, while
    // the pairwise consistency test is valid with the correct key, it then fails when the key
    // material is altered. To ease the certification process, we put this test in the FORCEFAIL
    // case of the POST tests.
    int rv = CCERR_OK;

    const struct fipspost_ecdsa_sign_kat *kat = &sign_kat_tvs[0];
    ccec_const_cp_t cp = kat->cp();

    CC_DECL_BP_WS(ws, bp);
    cc_size n = ccec_cp_n(cp);

    ccec_full_ctx_t full_key = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, full_key);

    CC_TEST_DISABLE_DIT_ASSERTS
    rv = ccec_x963_import_priv_ws(ws, cp, kat->dq_len, kat->dq, full_key);
    CC_TEST_ENABLE_DIT_ASSERTS
    if (rv) {
        failf("failed ccec_x963_import_priv");
        rv = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    // We first must verify that the consistency test passes.
    rv = ccec_pairwise_consistency_check_ws(ws, full_key, &ccrng_zero);
    if (rv) {
        failf("[PCT] CCEC_PAIRWISE_CONSISTENCY: unexpected FAILURE");
    } else {
        debugf("[PCT] CCEC_PAIRWISE_CONSISTENCY: expected SUCCESS");
    }

    // FORCEFAIL and Verify by Pairwise Consistency Check
    full_key->point->xyz[1] ^= 0x01;
    // We then must verify that the consistency test fails once the key has been modified.
    rv = ccec_pairwise_consistency_check_ws(ws, full_key, &ccrng_zero);
    if (rv) {
        debugf("[PCT] CCEC_PAIRWISE_CONSISTENCY: FORCEFAIL");
        rv = CCERR_OK;
    } else {
        failf("[PCT] CCEC_PAIRWISE_CONSISTENCY: unexpected SUCCESS");
        rv = CCERR_INTERNAL;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdsa_ws(cc_ws_t ws, uint32_t fips_mode)
{
    int rv = CCERR_OK;
    rv |= fipspost_post_ecdsa_kat_sign_ws(ws, fips_mode);
    rv |= fipspost_post_ecdsa_kat_verify_ws(ws, fips_mode);
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        rv |= fipspost_post_ecdsa_pairwise_ws(ws);
    }
    return rv;
}

int fipspost_post_ecdsa(uint32_t fips_mode)
{
    ccec_const_cp_t cp = ccec_cp_521(); // Largest curve in KAT vectors.
    CC_DECL_WORKSPACE_OR_FAIL(ws, FIPSPOST_POST_ECDSA_WORKSPACE_N(ccec_cp_n(cp)));
    const int rv = fipspost_post_ecdsa_ws(ws, fips_mode);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
