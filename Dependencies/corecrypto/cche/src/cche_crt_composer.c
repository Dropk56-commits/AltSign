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

#include "cche_crt_composer.h"
#include "cc_internal.h"
#include "cche_priv.h"
#include "ccpolyzp_po2cyc_scalar.h"

CC_PURE size_t struct_cche_crt_parameter_and_modulus_nof_n(void)
{
    return cc_ceiling(sizeof(struct cche_crt_parameter_and_modulus), sizeof_cc_unit()) +
           cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
}

CC_PURE size_t struct_cche_crt_composer_nof_n(size_t n)
{
    return cc_ceiling(sizeof(struct cche_crt_composer), sizeof_cc_unit()) + cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) +
           n * struct_cche_crt_parameter_and_modulus_nof_n();
}

CC_NONNULL_ALL CC_WARN_RESULT int
cche_crt_composer_init_ws(cc_ws_t ws, cche_crt_composer_t composer, cc_size nparams, const ccrns_int *plaintext_moduli)
{
    int rv = CCERR_OK;
    composer->nparams = nparams;
    ccrns_int moduli_product = 1;

    for (uint32_t index = 0; index < nparams; index++) {
        cche_crt_parameter_and_modulus_t parameter = CCHE_CRT_PARAMETER_AND_MODULUS(composer, index);
        parameter->plaintext_modulus = plaintext_moduli[index];
        bool overflow = cc_mul_overflow(plaintext_moduli[index], moduli_product, &moduli_product);
        if (overflow) {
            rv = CCERR_INTERNAL;
            cc_require(rv == CCERR_OK, errOut);
        }
        cczp_t zp = CCHE_CRT_PARAMETER_AND_MODULUS_CCZP(parameter);
        rv = ccpolyzp_po2cyc_modulus_to_cczp_ws(ws, zp, plaintext_moduli[index]);
        cc_require(rv == CCERR_OK, errOut);
    }
    cczp_t zp = CCHE_CRT_COMPOSER_CCZP(composer);
    rv = ccpolyzp_po2cyc_modulus_to_cczp_ws(ws, zp, moduli_product);
    cc_require(rv == CCERR_OK, errOut);
    composer->moduli_product = moduli_product;

    cc_unit mod_unit[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit reduced_mod[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit inversed_mod[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];

    for (uint32_t index = 0; index < nparams; index++) {
        cche_crt_parameter_and_modulus_t parameter = CCHE_CRT_PARAMETER_AND_MODULUS(composer, index);
        ccrns_int modulus_to_inverse = moduli_product / plaintext_moduli[index];
        ccpolyzp_po2cyc_rns_int_to_units(mod_unit, modulus_to_inverse);
        cczp_modn_ws(
            ws, CCHE_CRT_PARAMETER_AND_MODULUS_CCZP_CONST(parameter), reduced_mod, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, mod_unit);
        rv = cczp_inv_ws(ws, CCHE_CRT_PARAMETER_AND_MODULUS_CCZP_CONST(parameter), inversed_mod, reduced_mod);
        cc_require(rv == CCERR_OK, errOut);
        cczp_mul_ws(ws, CCHE_CRT_COMPOSER_CCZP(composer), parameter->plaintext_modulus_inverse_unit, mod_unit, inversed_mod);
    }
errOut:
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT int cche_crt_composer_compose_ws(cc_ws_t ws,
                                                               cche_crt_composer_const_t composer,
                                                               cc_size nresults,
                                                               int64_t *results,
                                                               const int64_t *values)
{
    if (composer->nparams == 1) {
        cc_memcpy(results, values, ccn_sizeof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * nresults));
        return CCERR_OK;
    }
    const cc_unit *cc_indexable zp_unit = cczp_prime(CCHE_CRT_COMPOSER_CCZP_CONST(composer));
    ccrns_int pval = ccpolyzp_po2cyc_units_to_rns_int(zp_unit);
    struct ccrns_modulus p_mod;
    int rv = ccrns_modulus_init_var_time_ws(ws, &p_mod, pval);
    cc_require(rv == CCERR_OK, errOut);
    for (size_t array_index = 0; array_index < nresults; array_index++) {
        ccrns_int composed_int = 0;
        for (size_t param_index = 0; param_index < composer->nparams; param_index++) {
            cche_crt_parameter_and_modulus_const_t parameter = CCHE_CRT_PARAMETER_AND_MODULUS_CONST(composer, param_index);
            ccrns_int non_neg_value =
                ccpolyzp_po2cyc_centered_to_rem(values[param_index * nresults + array_index], parameter->plaintext_modulus);
            ccrns_int mod_inv = ccpolyzp_po2cyc_units_to_rns_int(parameter->plaintext_modulus_inverse_unit);
            ccrns_int value_int = ccpolyzp_po2cyc_scalar_mul_mod(non_neg_value, mod_inv, &p_mod);
            composed_int = ccpolyzp_po2cyc_scalar_add_mod(composed_int, value_int, pval);
        }
        results[array_index] = ccpolyzp_po2cyc_rem_to_centered(composed_int, composer->moduli_product);
    }
errOut:
    return rv;
}

CC_PURE static cc_size CCHE_CRT_COMPOSE_WORKSPACE_N(cc_size nmoduli)
{
    cc_size composer = (struct_cche_crt_composer_nof_n((uint32_t)nmoduli));
    return composer + CC_MAX_EVAL(CCHE_CRT_COMPOSER_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                                  CCHE_CRT_COMPOSER_COMPOSE_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF));
}

CC_NONNULL_ALL CC_WARN_RESULT int cche_crt_compose_ws(cc_ws_t ws,
                                                      cc_size nresults,
                                                      int64_t *cc_counted_by(nresults) results,
                                                      const int64_t *values,
                                                      cc_size nmoduli,
                                                      const ccrns_int *cc_counted_by(nparams) plaintext_moduli)
{
    CC_DECL_BP_WS(ws, bp);
    int rv = CCERR_OK;
    struct cche_crt_composer *composer =
        (struct cche_crt_composer *)CC_ALLOC_WS(ws, struct_cche_crt_composer_nof_n((uint32_t)nmoduli));
    rv = cche_crt_composer_init_ws(ws, composer, nmoduli, plaintext_moduli);
    cc_require(rv == CCERR_OK, errOut);
    rv = cche_crt_composer_compose_ws(ws, composer, nresults, results, values);
    cc_require(rv == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT int cche_crt_compose(size_t nresults,
                                                   int64_t *cc_counted_by(nresults) results,
                                                   const int64_t *values,
                                                   size_t nplaintext_moduli,
                                                   const uint64_t *cc_counted_by(nplaintext_moduli) plaintext_moduli)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_CRT_COMPOSE_WORKSPACE_N(nplaintext_moduli));
    int rv = cche_crt_compose_ws(ws, nresults, results, values, nplaintext_moduli, plaintext_moduli);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
