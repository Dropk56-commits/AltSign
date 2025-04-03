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

#ifndef _CORECRYPTO_CCENTROPY_INTERNAL_H_
#define _CORECRYPTO_CCENTROPY_INTERNAL_H_

int ccentropy_get_seed_internal(ccentropy_ctx_t *ctx,
                                size_t seed_nbytes,
                                void *seed);

int ccentropy_add_entropy_internal(ccentropy_ctx_t *ctx,
                                   uint32_t entropy_nsamples,
                                   size_t entropy_nbytes,
                                   const void *entropy,
                                   bool *seed_ready);

#endif /* _CORECRYPTO_CCENTROPY_INTERNAL_H_ */
