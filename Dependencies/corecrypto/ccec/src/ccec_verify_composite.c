/* Copyright (c) (2014-2021,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccdigest_internal.h"

int ccec_verify_composite_digest_ws(cc_ws_t ws,
                                    ccec_pub_ctx_t key,
                                    size_t digest_len,
                                    const uint8_t *digest,
                                    const uint8_t *sig_r,
                                    const uint8_t *sig_s,
                                    cc_fault_canary_t fault_canary_out)
{
    CC_ASSERT_DIT_IS_ENABLED
    
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }
    cc_fault_canary_t fault_canary;

    int result = CCERR_INVALID_SIGNATURE;
    cc_size n = ccec_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    cc_require_action(
        (ccn_read_uint_internal(n, r, ccec_signature_r_s_size(key), sig_r) == 0), out, result = CCERR_PARAMETER);
    cc_require_action(
        (ccn_read_uint_internal(n, s, ccec_signature_r_s_size(key), sig_s) == 0), out, result = CCERR_PARAMETER);

    result = ccec_verify_internal_ws(ws, key, digest_len, digest, r, s, fault_canary);
    cc_require(result == CCERR_VALID_SIGNATURE, out);

    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }

out:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_verify_composite_digest(ccec_pub_ctx_t key,
                                 size_t digest_len,
                                 const uint8_t *digest,
                                 const uint8_t *sig_r,
                                 const uint8_t *sig_s,
                                 cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_COMPOSITE_DIGEST_WORKSPACE_N(ccec_ctx_n(key)));
    int rv = ccec_verify_composite_digest_ws(ws, key, digest_len, digest, sig_r, sig_s, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_verify_composite_msg_ws(cc_ws_t ws,
                                 ccec_pub_ctx_t key,
                                 const struct ccdigest_info *di,
                                 size_t msg_len, const uint8_t *msg,
                                 const uint8_t *sig_r, const uint8_t *sig_s,
                                 cc_fault_canary_t fault_canary_out)
{
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest_internal(di, msg_len, msg, digest);

    return ccec_verify_composite_digest_ws(ws,
                                           key,
                                           di->output_size, digest,
                                           sig_r, sig_s,
                                           fault_canary_out);
}

int ccec_verify_composite_msg(ccec_pub_ctx_t key,
                              const struct ccdigest_info *di,
                              size_t msg_len,
                              const uint8_t *msg,
                              const uint8_t *sig_r,
                              const uint8_t *sig_s,
                              cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_COMPOSITE_MSG_WORKSPACE_N(ccec_ctx_n(key)));
    int rv = ccec_verify_composite_msg_ws(ws,
                                          key,
                                          di,
                                          msg_len, msg,
                                          sig_r, sig_s,
                                          fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_verify_composite(ccec_pub_ctx_t key,
                          size_t digest_len,
                          const uint8_t *digest,
                          const uint8_t *sig_r,
                          const uint8_t *sig_s,
                          bool *valid)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    *valid = false;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_COMPOSITE_DIGEST_WORKSPACE_N(ccec_ctx_n(key)));
    int result = ccec_verify_composite_digest_ws(ws, key, digest_len, digest, sig_r, sig_s, NULL);
    CC_FREE_WORKSPACE(ws);
    
    switch (result) {
    case CCERR_VALID_SIGNATURE:
        *valid = true;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    case CCERR_INVALID_SIGNATURE:
        *valid = false;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    default:
        *valid = false;
    }
    return result;
}
