/* Copyright (c) (2011,2015,2016,2019,2021,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccn.h>
#include "ccn_internal.h"

size_t ccn_write_int_size_public_value(cc_size n, const cc_unit *s)
{
    size_t bl = ccn_bitlen_public_value(n, s);
    
    size_t bytes = (bl + 7 ) / 8;
    
    // High bit set, need leading zero.
    // If size is zero, insures we have a one byte content
    if ((bl % 8) == 0)
        ++bytes;
    
    return bytes;
}

size_t ccn_write_int_size(cc_size n, const cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccn_write_int_size_public_value(n, s);
}

void ccn_write_int_public_value(cc_size n, const cc_unit *s, size_t out_size, void *out)
{
    uint8_t *ix = out;
    // High bit set requires leading zero.
    if (ccn_bitlen_public_value(n, s) % 8 == 0) {
        *ix = 0x00;
        --out_size;
        ++ix;
    }

    ccn_write_uint_public_value(n, s, out_size, ix);
}

void ccn_write_int(cc_size n, const cc_unit *s, size_t out_size, void *out)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    return ccn_write_int_public_value(n, s, out_size, out);
}
