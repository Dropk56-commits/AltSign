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

#ifndef _CORECRYPTO_CCHE_CRT_COMPOSER_H
#define _CORECRYPTO_CCHE_CRT_COMPOSER_H

#include "cche_internal.h"
#include "cczp_priv.h"

struct cche_crt_parameter_and_modulus {
    ccrns_int plaintext_modulus;
    cc_unit plaintext_modulus_inverse_unit[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit data[]; // stores a cczp
};

struct cche_crt_composer {
    cc_size nparams;
    ccrns_int moduli_product;
    cc_unit data[]; // stores a cczp followed by all the pre-computed cche_crt_parameter_and_modulus
};

typedef struct cche_crt_parameter_and_modulus *cche_crt_parameter_and_modulus_t;
typedef const struct cche_crt_parameter_and_modulus *cche_crt_parameter_and_modulus_const_t;
typedef struct cche_crt_composer *cche_crt_composer_t;
typedef const struct cche_crt_composer *cche_crt_composer_const_t;

/// @brief Returns pointer to the cczp in cche_crt_parameter_and_modulus
/// @param parameter cche_crt_parameter_and_modulus
#define CCHE_CRT_PARAMETER_AND_MODULUS_CCZP(parameter) ((cczp_t)((parameter)->data))
#define CCHE_CRT_PARAMETER_AND_MODULUS_CCZP_CONST(parameter) ((cczp_const_t)(const cc_unit *)((parameter)->data))

/// @brief Returns pointer to the cczp in the cche_crt_composer
/// @param composer the cche_crt_composer
#define CCHE_CRT_COMPOSER_CCZP(composer) ((cczp_t)((composer)->data))
#define CCHE_CRT_COMPOSER_CCZP_CONST(composer) ((cczp_const_t)(const cc_unit *)((composer)->data))

/// @brief Returns the cche_crt_parameter_and_modulus in the cche_crt_composer
/// @param composer the cche_crt_composer
#define CCHE_CRT_PARAMETER_AND_MODULUS(composer, i)                                                                    \
    ((cche_crt_parameter_and_modulus_t)((cc_unit *)((composer)->data) + cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) + \
                                        (i) * struct_cche_crt_parameter_and_modulus_nof_n()))
#define CCHE_CRT_PARAMETER_AND_MODULUS_CONST(composer, i)                                    \
    ((cche_crt_parameter_and_modulus_const_t)((const cc_unit *)((composer)->data) +          \
                                              cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) + \
                                              (i) * struct_cche_crt_parameter_and_modulus_nof_n()))

// Leaks plaintext_moduli through timing
CC_NONNULL_ALL CC_WARN_RESULT int
cche_crt_composer_init_ws(cc_ws_t ws, cche_crt_composer_t composer, cc_size nmoduli, const ccrns_int *plaintext_moduli);

CC_NONNULL_ALL CC_WARN_RESULT int cche_crt_composer_compose_ws(cc_ws_t ws,
                                                               cche_crt_composer_const_t composer,
                                                               cc_size nresults,
                                                               int64_t *results,
                                                               const int64_t *values);

CC_NONNULL_ALL CC_WARN_RESULT int cche_crt_compose_ws(cc_ws_t ws,
                                                      cc_size nresults,
                                                      int64_t *cc_counted_by(nresults) results,
                                                      const int64_t *cc_counted_by(nresults *nmoduli) values,
                                                      cc_size nmoduli,
                                                      const ccrns_int *cc_counted_by(nmoduli) plaintext_moduli);

/// @brief Returns the number of cc_units required to store cche_crt_parameter_and_modulus
CC_PURE size_t struct_cche_crt_parameter_and_modulus_nof_n(void);

/// @brief Returns the number of cc_units required to store cche_crt_composer
/// @param nmoduli Number of moduli
CC_PURE size_t struct_cche_crt_composer_nof_n(size_t nmoduli);

#endif /* _CORECRYPTO_CCHE_CRT_COMPOSER_H */
