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

#ifndef _CORECRYPTO_CCCHACHA20POLY1305_INTERNAL_H_
#define _CORECRYPTO_CCCHACHA20POLY1305_INTERNAL_H_

CC_PTRCHECK_CAPABLE_HEADER()

/*
int ccchacha20_init_internal(ccchacha20_ctx *ctx, const uint8_t *cc_counted_by(CCCHACHA20_KEY_NBYTES) key);
int ccchacha20_setnonce_internal(ccchacha20_ctx *ctx, const uint8_t *cc_counted_by(CCCHACHA20_NONCE_NBYTES) nonce);
int ccchacha20_setcounter_internal(ccchacha20_ctx *ctx, uint32_t counter);
int ccchacha20_update_internal(ccchacha20_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);
int ccchacha20_final_internal(ccchacha20_ctx *ctx);
*/


#endif /* _CORECRYPTO_CCCHACHA20POLY1305_INTERNAL_H_ */
