/* Copyright (c) (2021,2022,2024) Apple Inc. All rights reserved.
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

size_t ccctr_context_size(const struct ccmode_ctr *mode)
{
    return mode->size;
}

size_t ccctr_block_size(const struct ccmode_ctr *mode)
{
    return mode->block_size;
}

int ccctr_init_internal(const struct ccmode_ctr *mode,
                        ccctr_ctx *ctx,
                        size_t key_len,
                        const void *cc_sized_by(key_len) key,
                        const void *cc_indexable iv)
{
    CC_ASSERT_DIT_IS_ENABLED

    return mode->init(mode, ctx, key_len, key, iv);
}

int ccctr_init(const struct ccmode_ctr *mode,
               ccctr_ctx *ctx,
               size_t key_len,
               const void *cc_sized_by(key_len) key,
               const void *cc_indexable iv)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccctr_init_internal(mode, ctx, key_len, key, iv);
}

int ccctr_update_internal(const struct ccmode_ctr *mode,
                          ccctr_ctx *ctx,
                          size_t nbytes,
                          const void *cc_sized_by(nbytes) in,
                          void *cc_sized_by(nbytes) out)
{
    CC_ASSERT_DIT_IS_ENABLED

    return mode->ctr(ctx, nbytes, in, out);
}

int ccctr_update(const struct ccmode_ctr *mode,
                 ccctr_ctx *ctx,
                 size_t nbytes,
                 const void *cc_sized_by(nbytes) in,
                 void *cc_sized_by(nbytes) out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccctr_update_internal(mode, ctx, nbytes, in, out);
}

int ccctr_one_shot_internal(const struct ccmode_ctr *mode,
                            size_t key_len,
                            const void *cc_sized_by(key_len) key,
                            const void *cc_indexable iv,
                            size_t nbytes,
                            const void *cc_sized_by(nbytes) in,
                            void *cc_sized_by(nbytes) out)
{
    CC_ASSERT_DIT_IS_ENABLED

    int rc;
    ccctr_ctx_decl(mode->size, ctx);
    rc = ccctr_init_internal(mode, ctx, key_len, key, iv);
    if (rc == 0) {
        rc = ccctr_update_internal(mode, ctx, nbytes, in, out);
    }
    ccctr_ctx_clear(mode->size, ctx);
    return rc;
}

int ccctr_one_shot(const struct ccmode_ctr *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *cc_indexable iv,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccctr_one_shot_internal(mode, key_len, key, iv, nbytes, in, out);
}
