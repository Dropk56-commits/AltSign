/* Copyright (c) (2010-2012,2015-2017,2019,2021,2022,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdigest.h>
#include "fipspost_trace.h"
#include "ccdigest_internal.h"

void ccdigest_internal(const struct ccdigest_info *di, size_t len,
                       const void *data, void *digest) {
    CC_ASSERT_DIT_IS_ENABLED

    FIPSPOST_TRACE_EVENT;

    ccdigest_di_decl(di, dc);
    ccdigest_init_internal(di, dc);
    ccdigest_update_internal(di, dc, len, data);
    ccdigest_final(di, dc, digest);
    ccdigest_di_clear(di, dc);
}


void alt_ccdigest(const struct ccdigest_info *di, size_t len,
                  const void *data, void *digest) {
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccdigest_internal(di, len, data, digest);
}
