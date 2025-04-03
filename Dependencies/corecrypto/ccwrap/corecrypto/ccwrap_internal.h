/* Copyright (c) (2018,2019,2022,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCWRAP_INTERNAL_H_
#define _CORECRYPTO_CCWRAP_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccwrap_priv.h>

/*!
  @function ccwrap_argsvalid
  @abstract Validate arguments to @p ccwrap functions.

  @param      ecb        Definition of an ECB implementation
  @param      pbytes     Length in bytes of the unwrapped key
  @param      cbytes     Length in bytes of the wrapped key

  @result     true iff valid, otherwise false.
*/
CC_NONNULL((1))
bool ccwrap_argsvalid(const struct ccmode_ecb *ecb,
                      size_t pbytes,
                      size_t cbytes);

CC_NONNULL((1, 2, 4, 5, 6, 7))
int ccwrap_auth_decrypt_withiv_internal(const struct ccmode_ecb *ecb_mode,
                                        ccecb_ctx *ctx,
                                        size_t nbytes,
                                        const void *in,
                                        size_t *obytes,
                                        void *out,
                                        const void *iv);

CC_NONNULL((1, 2, 4, 5, 6, 7))
int ccwrap_auth_encrypt_withiv_internal(const struct ccmode_ecb *ecb_mode,
                                        ccecb_ctx *ctx,
                                        size_t nbytes,
                                        const void *in,
                                        size_t *obytes,
                                        void *out,
                                        const void *iv);

CC_NONNULL((1, 2, 4, 5, 6))
int ccwrap_auth_decrypt_internal(const struct ccmode_ecb *ecb_mode,
                                 ccecb_ctx *ctx,
                                 size_t nbytes,
                                 const void *in,
                                 size_t *obytes,
                                 void *out);

CC_NONNULL((1, 2, 4, 5, 6))
int ccwrap_auth_encrypt_internal(const struct ccmode_ecb *ecb_mode,
                                 ccecb_ctx *ctx,
                                 size_t nbytes,
                                 const void *in,
                                 size_t *obytes,
                                 void *out);
    
#endif  /* _CORECRYPTO_CCWRAP_INTERNAL_H_ */
