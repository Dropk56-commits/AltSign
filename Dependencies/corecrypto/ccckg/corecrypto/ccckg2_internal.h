/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCKG2_INTERNAL_H_
#define _CORECRYPTO_CCCKG2_INTERNAL_H_

#include <corecrypto/ccckg2.h>
#include "ccckg_internal.h"
#include "cc_internal.h"
#include "cc_memory.h"

struct ccckg2_params {
    ccckg_version version;
    ccec_const_cp_t (*CC_SPTR(ccckg2_params, cp))(void);
    const struct ccdigest_info* (*CC_SPTR(ccckg2_params, di))(void);
};

// Keep in sync with struct ccckg_ctx.
struct ccckg2_ctx {
    ccckg_version version;
    ccec_const_cp_t cp;
    const struct ccdigest_info *di;
    struct ccrng_state *rng; // unused
    ccckg_state_t state;
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

#define ccckg2_ctx_decl(_params_, _name_) cc_ctx_decl(struct ccckg2_ctx, ccckg2_sizeof_ctx(_params_), _name_)
#define ccckg2_ctx_clear(_params_, _name_) cc_clear(ccckg2_sizeof_ctx(_params_), _name_)

// The local scalar.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
cc_unit* ccckg2_ctx_s(ccckg2_ctx_t ctx)
{
    return ccckg_ctx_s((ccckg_ctx_t)ctx);
}

// The second local scalar.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
cc_unit* ccckg2_ctx_r(ccckg2_ctx_t ctx)
{
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    return ccckg2_ctx_s(ctx) + ccec_cp_n(cp);
}

// The contributor's commitment share R = r * G.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
uint8_t* ccckg2_ctx_rG(ccckg2_ctx_t ctx)
{
    ccec_const_cp_t cp = ccckg2_ctx_cp(ctx);
    return (uint8_t *)ccckg2_ctx_r(ctx) + ccn_sizeof_n(ccec_cp_n(cp));
}

// The contributor's commitment hash.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
uint8_t* ccckg2_ctx_c(ccckg2_ctx_t ctx)
{
    return ccckg2_ctx_rG(ctx);
}

CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_commitment_internal(const struct ccdigest_info *di)
{
    return di->output_size;
}

CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_share_internal(ccec_const_cp_t cp)
{
    // Two EC points.
    return ccec_export_pub_size_cp(cp) * 2;
}

CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_opening_internal(ccec_const_cp_t cp)
{
    // A scalar plus a point.
    return ccec_cp_order_size(cp) + ccec_export_pub_size_cp(cp);
}

/*! @function ccckg2_derive_sk
 @abstract Derive the shared symmetric secret.

 @param ctx       CKG context
 @param R_bytes   Public point R or R'
 @param P         Shared point P.
 @param sk_nbytes Desired length of SK in bytes
 @param sk        Output buffer for SK
 @param rng       RNG instance.

 @return Size of a CKG context
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_derive_sk(ccckg2_ctx_t ctx,
                     const uint8_t *R_bytes,
                     ccec_pub_ctx_t P,
                     size_t sk_nbytes,
                     uint8_t *sk,
                     struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_derive_sk_ws(cc_ws_t ws,
                        ccckg2_ctx_t ctx,
                        const uint8_t *R_bytes,
                        ccec_pub_ctx_t P,
                        size_t sk_nbytes,
                        uint8_t *sk,
                        struct ccrng_state *rng);

#endif /* _CORECRYPTO_CCCKG2_INTERNAL_H_ */
