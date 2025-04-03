/* Copyright (c) (2019,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCKG_INTERNAL_H_
#define _CORECRYPTO_CCCKG_INTERNAL_H_

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccckg.h>
#include "cc_internal.h"
#include "cc_memory.h"

#define CCCKG_HASH_MAX_NBYTES MAX_DIGEST_OUTPUT_SIZE
#define CCCKG_CURVE_MAX_NBYTES cc_ceiling(521, 8)

/*
 Collaborative Key Generation state machine.

 An initialized context will always start at INIT.

 VALID: INIT -> COMMIT -> FINISH
 VALID: INIT -> SHARE -> FINISH
 */
#define CCCKG_STATE_INIT   0
#define CCCKG_STATE_COMMIT 1
#define CCCKG_STATE_SHARE  2
#define CCCKG_STATE_FINISH 3

#define CCCKG_EXPECT_STATE(_st_)                      \
    if (ccckg_ctx_state(ctx) != CCCKG_STATE_##_st_) { \
        return CCERR_CALL_SEQUENCE;                   \
    }

#define CCCKG_SET_STATE(_st_) ccckg_ctx_state(ctx) = CCCKG_STATE_##_st_

typedef enum {
    CCCKG_VERSION_1 = 1,
    CCCKG_VERSION_2 = 2
} ccckg_version;

typedef uint8_t ccckg_state_t;

struct ccckg_ctx {
    ccckg_version version;
    ccec_const_cp_t cp;
    const struct ccdigest_info *di;
    struct ccrng_state *rng;
    ccckg_state_t state;
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

#define ccckg_ctx_version(ctx) (ctx->version)

#define ccckg_ctx_rng(ctx)   (ctx->rng)
#define ccckg_ctx_state(ctx) (ctx->state)

#define ccckg_ctx_decl(_cp_, _di_, _name_) cc_ctx_decl(struct ccckg_ctx, ccckg_sizeof_ctx(_cp_, _di_), _name_)
#define ccckg_ctx_clear(_cp_, _di_, _name_) cc_clear(ccckg_sizeof_ctx(_cp_, _di_), _name_)

// The local scalar.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
cc_unit* ccckg_ctx_s(ccckg_ctx_t ctx)
{
    return ctx->ccn;
}

// The local nonce.
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
uint8_t* ccckg_ctx_r(ccckg_ctx_t ctx)
{
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    return (uint8_t *)ccckg_ctx_s(ctx) + ccn_sizeof_n(ccec_cp_n(cp));
}

// The contributor's commitment (owner-only).
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT
uint8_t* ccckg_ctx_c(ccckg_ctx_t ctx)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    return ccckg_ctx_r(ctx) + ccn_sizeof_size(di->output_size);
}

/*! @function ccckg_contributor_finish_derive_p_ws
 @abstract Derive the shared point P.

 @param ws      Workspace
 @param ctx     CKG context
 @param S_bytes Owner share S'.
 @param P       Output point P.
 @param rng     RNG instance.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg_contributor_finish_derive_p_ws(cc_ws_t ws,
                                         ccckg_ctx_t ctx,
                                         const uint8_t *S_bytes,
                                         ccec_pub_ctx_t P,
                                         struct ccrng_state *rng);

/*! @function ccckg_owner_finish_derive_p
 @abstract Derive the shared point P.

 @param ctx     CKG context
 @param s       Contributor scalar s.
 @param P       Output point P.
 @param rng     RNG instance.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg_owner_finish_derive_p(ccckg_ctx_t ctx,
                                const uint8_t *s,
                                ccec_full_ctx_t P,
                                struct ccrng_state *rng);

/*! @function ccckg_derive_sk
 @abstract Derive the shared symmetric secret.

 @param ctx        CKG context
 @param x          X coordinate of the shared point
 @param r1         Contributor's nonce
 @param r2         Owner's nonce
 @param key_nbytes Desired length of SK in bytes
 @param key        Output buffer for SK

 @return Size of a CKG context
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg_derive_sk(ccckg_ctx_t ctx, const cc_unit *x, const uint8_t *r1, const uint8_t *r2, size_t key_nbytes, uint8_t *key);

#endif /* _CORECRYPTO_CCCKG_INTERNAL_H_ */
