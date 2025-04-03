/* Copyright (c) (2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCN_PV_H
#define _CORECRYPTO_CCN_PV_H

CC_PTRCHECK_CAPABLE_HEADER()

/*
 ccder requires these "public value" variants. ccder cannot import
 ccn_internal.h due to firebloom issues. So we declare them here
 as to not have to declare them publicly.
 */

CC_PURE CC_NONNULL((2)) size_t ccn_write_uint_size_public_value(cc_size n, const cc_unit *cc_counted_by(n) s);

CC_NONNULL((2, 4))
int ccn_read_uint_public_value(cc_size n, cc_unit *cc_counted_by(n) r, size_t data_nbytes, const uint8_t *cc_sized_by(data_nbytes) data);

CC_PURE CC_NONNULL((2))
size_t ccn_write_int_size_public_value(cc_size n, const cc_unit *cc_counted_by(n) s);

CC_NONNULL((2, 4))
void ccn_write_int_public_value(cc_size n, const cc_unit *cc_counted_by(n) s, size_t out_size, void *cc_sized_by(out_size) out);

#endif /* _CORECRYPTO_CCN_PV_H */
