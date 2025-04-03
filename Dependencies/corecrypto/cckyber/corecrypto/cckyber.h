/* Copyright (c) (2022-2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCKYBER_H_
#define _CORECRYPTO_CCKYBER_H_

#include <corecrypto/cckem.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

const struct cckem_info *cckem_kyber768(void);
const struct cckem_info *cckem_kyber1024(void);

CC_END_DECLS

#endif /* _CORECRYPTO_CCKYBER_H_ */
