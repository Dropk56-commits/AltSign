/* Copyright (c) (2010,2011,2015,2019-2022,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"

void ccdigest_init_internal(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
    CC_ASSERT_DIT_IS_ENABLED

    ccdigest_copy_state(di, ccdigest_state_ccn(di, ctx), di->initial_state);
    ccdigest_nbits(di, ctx) = 0;
    ccdigest_num(di, ctx) = 0;
}


void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccdigest_init_internal(di, ctx);
}
