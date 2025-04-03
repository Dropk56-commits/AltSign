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

#include <corecrypto/cc_priv.h>
#include "cc_debug.h"

// CC_UNUSED on all the parameters because cc_printf is defined empty for some targets.

void cc_print(CC_UNUSED const char *label, CC_UNUSED size_t count, CC_UNUSED const uint8_t *s) {
    cc_printf("%s { %zu, ",label, count);
    for (size_t ix=0; ix<count ; ix++) {
        cc_printf("%.02x", s[ix]);
    }
    cc_printf(" }\n");
}
