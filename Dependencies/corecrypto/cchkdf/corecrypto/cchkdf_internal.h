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

#ifndef _CORECRYPTO_CCHKDF_INTERNAL_H_
#define _CORECRYPTO_CCHKDF_INTERNAL_H_

int cchkdf_internal(const struct ccdigest_info *di,
                    size_t ikm_nbytes,
                    const void *ikm,
                    size_t salt_nbytes,
                    const void *salt,
                    size_t info_nbytes,
                    const void *info,
                    size_t dk_nbytes,
                    void *dk);

int cchkdf_extract_internal(const struct ccdigest_info *di,
                            size_t salt_nbytes,
                            const void *salt,
                            size_t ikm_nbytes,
                            const void *ikm,
                            void *prk);

int cchkdf_expand_internal(const struct ccdigest_info *di,
                           size_t prk_nbytes,
                           const void *prk,
                           size_t info_nbytes,
                           const void *info,
                           size_t dk_nbytes,
                           void *dk);


#endif /* _CORECRYPTO_CCHKDF_INTERNAL_H_ */
