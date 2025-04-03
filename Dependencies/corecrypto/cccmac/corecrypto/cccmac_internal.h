/* Copyright (c) (2013,2015-2019,2022,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMAC_INTERNAL_H
#define _CORECRYPTO_CCMAC_INTERNAL_H

#include <corecrypto/cc.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/cccmac.h>

// Sub key generation
int cccmac_generate_subkeys(const struct ccmode_cbc *cbc, size_t key_nbytes,
                            const void *key, uint8_t *subkey1, uint8_t *subkey2);

// Doubling operation in sub key generation
void cccmac_sl_test_xor(uint8_t *r, const uint8_t *s);

int cccmac_init_internal(const struct ccmode_cbc *cbc,
                         cccmac_ctx_t ctx,
                         size_t key_nbytes, const void *cc_sized_by(key_nbytes) key);

int cccmac_update_internal(cccmac_ctx_t ctx,
                           size_t data_nbytes, const void *cc_sized_by(data_nbytes) data);

int cccmac_final_generate_internal(cccmac_ctx_t ctx,
                                   size_t mac_nbytes, void *cc_sized_by(mac_nbytes) mac);

int cccmac_final_verify_internal(cccmac_ctx_t ctx,
                                 size_t expected_mac_nbytes, const void *cc_sized_by(expected_mac_nbytes) expected_mac);

int cccmac_one_shot_generate_internal(const struct ccmode_cbc *cbc,
                                      size_t key_nbytes, const void *cc_sized_by(key_nbytes) key,
                                      size_t data_nbytes, const void *cc_sized_by(data_nbytes) data,
                                      size_t mac_nbytes, void *cc_sized_by(mac_nbytes) mac);

#endif // _CORECRYPTO_CCMAC_INTERNAL_H
