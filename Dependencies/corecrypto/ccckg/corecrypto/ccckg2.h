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

#ifndef _CORECRYPTO_CCCKG2_H_
#define _CORECRYPTO_CCCKG2_H_

#include <corecrypto/ccckg.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

/*
 * Collaborative Key Generation (CKG) protocol v2.
 */

struct ccckg2_params;
typedef const struct ccckg2_params *ccckg2_params_t;

// CKG parameters for P-224 with SHA-256, protocol version 2.
CC_CONST ccckg2_params_t ccckg2_params_p224_sha256_v2(void);

struct ccckg2_ctx;
typedef struct ccckg2_ctx *ccckg2_ctx_t;

CC_NONNULL_ALL CC_WARN_RESULT
ccec_const_cp_t ccckg2_ctx_cp(ccckg2_ctx_t ctx);

CC_NONNULL_ALL CC_WARN_RESULT
const struct ccdigest_info* ccckg2_ctx_di(ccckg2_ctx_t ctx);

/*! @function ccckg2_sizeof_ctx
 @abstract Returns the size of a CKG context.

 @param params CKG parameters.

 @return Size of a CKG context.
 */
CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_ctx(ccckg2_params_t params);

/*! @function ccckg2_sizeof_commitment
 @abstract Returns the size of a commitment.

 @param params CKG parameters.

 @return Size of a commitment.
 */
CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_commitment(ccckg2_params_t params);

/*! @function ccckg2_sizeof_share
 @abstract Returns the size of a share.

 @param params CKG parameters.

 @return Size of a share.
 */
CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_share(ccckg2_params_t params);

/*! @function ccckg2_sizeof_opening
 @abstract Returns the size of an opened commitment (called opening).

 @param params CKG parameters.

 @return Size of an opening.
 */
CC_NONNULL_ALL CC_WARN_RESULT
size_t ccckg2_sizeof_opening(ccckg2_params_t params);

/*! @function ccckg2_init
 @abstract Initialize a CKG context.

 @param ctx CKG context.
 @param params CKG parameters.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_init(ccckg2_ctx_t ctx, ccckg2_params_t params);

/*! @function ccckg2_contributor_commit
 @abstract Generates a contributor commitment.

 @param ctx               CKG context.
 @param commitment_nbytes Length of the commitment buffer (must be equal to ccckg2_sizeof_commitment).
 @param commitment        Commitment output buffer.
 @param rng               RNG instance.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_contributor_commit(ccckg2_ctx_t ctx, size_t commitment_nbytes, uint8_t *commitment, struct ccrng_state *rng);

/*! @function ccckg2_owner_generate_share
 @abstract Generates an owner share.

 @param ctx               CKG context.
 @param commitment_nbytes Length of the commitment buffer in bytes.
 @param commitment        Commitment input buffer.
 @param share_nbytes      Length of the share buffer in bytes (must be equal to ccckg2_sizeof_share).
 @param share             Share output buffer.
 @param rng               RNG instance.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_owner_generate_share(ccckg2_ctx_t ctx,
                                size_t commitment_nbytes,
                                const uint8_t *cc_counted_by(commitment_nbytes) commitment,
                                size_t share_nbytes,
                                uint8_t *cc_counted_by(share_nbytes) share,
                                struct ccrng_state *rng);

/*! @function ccckg2_contributor_finish
 @abstract Finishes the contributor protocol flow by opening the commitment
           and computing the shared point and symmetric secret.

 @param ctx            CKG context.
 @param share_nbytes   Length of the share buffer (must be equal to ccckg2_sizeof_share).
 @param share          Share input buffer.
 @param opening_nbytes Length of the opening (must be equal to ccckg2_sizeof_opening).
 @param opening        Opening output buffer.
 @param P              Shared public point (output).
 @param sk_nbytes      Desired length of the symmetric secret.
 @param sk             Output buffer for the symmetric secret.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_contributor_finish(ccckg2_ctx_t ctx,
                              size_t share_nbytes,
                              const uint8_t *cc_counted_by(share_nbytes) share,
                              size_t opening_nbytes,
                              uint8_t *cc_counted_by(opening_nbytes) opening,
                              ccec_pub_ctx_t P,
                              size_t sk_nbytes,
                              uint8_t *cc_counted_by(sk_nbytes) sk,
                              struct ccrng_state *rng);

/*! @function ccckg2_owner_finish
 @abstract Finishes the owner protocol flow by computing the shared point and
           symmetric secret.

 @param ctx            CKG context.
 @param opening_nbytes Length of the opening in bytes (must be equal to ccckg2_sizeof_opening).
 @param opening        Opening input buffer.
 @param P              Shared public point (output).
 @param sk_nbytes      Desired length of the symmetric secret in bytes.
 @param sk             Output buffer for the symmetric secret.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccckg2_owner_finish(ccckg2_ctx_t ctx,
                        size_t opening_nbytes,
                        const uint8_t *cc_counted_by(opening_nbytes) opening,
                        ccec_full_ctx_t P,
                        size_t sk_nbytes,
                        uint8_t *cc_counted_by(sk_nbytes) sk,
                        struct ccrng_state *rng);

CC_END_DECLS

#endif // _CORECRYPTO_CCCKG2_H_
