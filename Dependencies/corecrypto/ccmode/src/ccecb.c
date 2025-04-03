/* Copyright (c) (2021-2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode.h>
#include "ccmode_internal.h"

size_t ccecb_context_size(const struct ccmode_ecb *mode)
{
    return mode->size;
}

size_t ccecb_block_size(const struct ccmode_ecb *mode)
{
    return mode->block_size;
}

int ccecb_init_internal(const struct ccmode_ecb *mode,
                        ccecb_ctx *ctx,
                        size_t key_len,
                        const void *cc_sized_by(key_len) key)
{
    CC_ASSERT_DIT_IS_ENABLED

    return mode->init(mode, ctx, key_len, key);
}

int ccecb_init(const struct ccmode_ecb *mode,
               ccecb_ctx *ctx,
               size_t key_len,
               const void *cc_sized_by(key_len) key)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccecb_init_internal(mode, ctx, key_len, key);
}

int ccecb_update_internal(const struct ccmode_ecb *mode,
                 const ccecb_ctx *ctx,
                 size_t nblocks,
                 const void *cc_indexable in,
                 void *cc_indexable out)
{
    CC_ASSERT_DIT_IS_ENABLED

    return mode->ecb(ctx, nblocks, in, out);
}

int ccecb_update(const struct ccmode_ecb *mode,
                 const ccecb_ctx *ctx,
                 size_t nblocks,
                 const void *cc_indexable in,
                 void *cc_indexable out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccecb_update_internal(mode, ctx, nblocks, in, out);
}

static int ccecb_one_shot_explicit_internal(const struct ccmode_ecb *mode,
                                            size_t key_len,
                                            size_t block_size,
                                            size_t nblocks,
                                            const void *cc_sized_by(key_len) key,
                                            const void *cc_sized_by(block_size * nblocks) in,
                                            void *cc_sized_by(block_size * nblocks) out)
{
    CC_ASSERT_DIT_IS_ENABLED

    if (block_size != mode->block_size) {
        return CCERR_PARAMETER; /* Invalid input size */
    }

    int rc;
    ccecb_ctx_decl(mode->size, ctx);
    rc = mode->init(mode, ctx, key_len, key);
    if (rc == 0) {
        rc = mode->ecb(ctx, nblocks, in, out);
    }
    ccecb_ctx_clear(mode->size, ctx);
    return rc;
}

int ccecb_one_shot_explicit(const struct ccmode_ecb *mode,
                            size_t key_len,
                            size_t block_size,
                            size_t nblocks,
                            const void *cc_sized_by(key_len) key,
                            const void *cc_sized_by(block_size * nblocks) in,
                            void *cc_sized_by(block_size * nblocks) out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB
    
    return ccecb_one_shot_explicit_internal(mode, key_len, block_size, nblocks, key, in, out);
}

int ccecb_one_shot(const struct ccmode_ecb *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   size_t nblocks,
                   const void *cc_unsafe_indexable in,
                   void *cc_unsafe_indexable out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB
    return ccecb_one_shot_explicit_internal(mode,
                                            key_len,
                                            mode->block_size,
                                            nblocks,
                                            key,
                                            cc_unsafe_forge_bidi_indexable(in, mode->block_size * nblocks),
                                            cc_unsafe_forge_bidi_indexable(out, mode->block_size * nblocks));
}


