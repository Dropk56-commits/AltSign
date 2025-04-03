/* Copyright (c) (2010,2011,2015,2016,2019,2021,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/cchmac.h>
#include "ccdigest_internal.h"
#include "cchmac_internal.h"

void cchmac_update_internal(const struct ccdigest_info *di, cchmac_ctx_t hc,
                            size_t data_len, const void *data) {
    CC_ASSERT_DIT_IS_ENABLED

    ccdigest_update_internal(di, cchmac_digest_ctx(di, hc), data_len, data);
}

void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc,
                   size_t data_len, const void *data) {
    CC_ENSURE_DIT_ENABLED_WITH_SB

    cchmac_update_internal(di, hc, data_len, data);
}
