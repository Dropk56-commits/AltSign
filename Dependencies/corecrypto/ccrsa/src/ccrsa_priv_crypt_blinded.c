/* Copyright (c) (2010-2012,2014-2021,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MASK  (((((cc_unit)1)<<(SCA_MASK_BITSIZE-1))-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK (6 * SCA_MASK_N)   // p, dp, mp, q, dq, mq

cc_static_assert(SCA_MASK_N == 1, "we use ccn_mul1() for masks");

// Modulus blinding.
// Initializes `zp_masked`, blinding the prime factor of `zp`.
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_crt_init_pq_star_ws(cc_ws_t ws,
                                     cczp_const_t zp,
                                     cczp_t zp_masked,
                                     cc_unit rnd)
{
    cc_size np = cczp_n(zp);
    CCZP_N(zp_masked) = np + SCA_MASK_N;
    *(CCZP_PRIME(zp_masked) + np) = ccn_mul1(np, CCZP_PRIME(zp_masked), cczp_prime(zp), SCA_MASK_MASK & (rnd | 1));
    return cczp_mm_init_ws(ws, zp_masked, np + SCA_MASK_N, NULL);
}

// Base blinding and CRT share computation.
// Blinds `x` by adding a random multiple of `p`.
// Computes a single share of the CRT, the blinded `x` mod the blinded modulus.
CC_NONNULL_ALL
static void ccrsa_crt_exp_mod_pq_star_ws(cc_ws_t ws,
                                         cczp_const_t zm,
                                         cczp_const_t zp,
                                         cczp_const_t zp_masked,
                                         const cc_unit *x,
                                         const cc_unit *d,
                                         cc_unit *sp,
                                         cc_unit rnd[2])
{
    cc_size n = cczp_n(zp_masked);
    cc_size np = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp  = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, 1 * n);

    // mp = m + k.p mod p_star
    ccn_setn(cczp_n(zm) + 1, tmp, np, cczp_prime(zp));
    ccn_set_bit(tmp, 0, 0); // p - 1
    ccn_set(np, tmp2, d);   // dp

    tmp2[np] = ccn_addmul1(np, tmp2, tmp, SCA_MASK_MASK & rnd[0]);       // tmp2 = dp + rnd*(p-1)
    tmp[np] = ccn_mul1(np, tmp, cczp_prime(zp), SCA_MASK_MASK & rnd[1]); // tmp = mask*p
    ccn_addn(cczp_n(zm) + 1, tmp, tmp, cczp_n(zm), x);                   // tmp = x + mask*p
    cczp_modn_ws(ws, zp_masked, tmp, cczp_n(zm) + 1, tmp);               // tmp = x + mask*p mod p_star

    // sp = (tmp ^ dp) mod p_star
    cczp_to_ws(ws, zp_masked, tmp, tmp);
    int rv = cczp_power_ws(ws, zp_masked, sp, tmp, cczp_bitlen(zp) + SCA_MASK_BITSIZE, tmp2);

    // Ignoring error code; arguments guaranteed to be valid.
    // Public key validation will follow, we don't want to early abort here.
    cc_assert(rv == CCERR_OK);
    (void)rv;

    cczp_from_ws(ws, zp_masked, sp, sp);
    CC_FREE_BP_WS(ws, bp);
}

// Garner recombination.
// Recombines two blinded CRT shares.
CC_NONNULL_ALL
static void ccrsa_crt_combine_pq_star_ws(cc_ws_t ws,
                                         ccrsa_full_ctx_t fk,
                                         cczp_const_t zp_masked,
                                         const cc_unit *sp,
                                         const cc_unit *sq,
                                         cc_unit *r)
{
    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    cc_size n = cczp_n(zp_masked);
    cc_size np = cczp_n(zp);
    cc_size nq = cczp_n(zq);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp1 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, 1 * n);
    cc_unit *tmp3 = CC_ALLOC_WS(ws, 1 * n);

    ccn_setn(n + 2, tmp1, n, cczp_prime(zp_masked));
    ccn_shift_left_multi(n + 2, tmp1, tmp1, SCA_MASK_BITSIZE + 1); // 2*SCA_MASK_MASK*cstp*p
    ccn_addn(n + 2, tmp1, tmp1, n, sp);                            // 2*SCA_MASK_MASK*cstp*p + sp
    cc_unit b = ccn_subn(n + 2, tmp1, tmp1, nq + SCA_MASK_N, sq);  // tmp1: t = (sp + (2*SCA_MASK_MASK)*p_star) - sq

    // There should be no borrow.
    cc_assert(b == 0);
    (void)b;

    cczp_modn_ws(ws, zp_masked, tmp3, n + 2, tmp1);    // t mod p_star
    ccn_setn(n, tmp1, np, ccrsa_ctx_private_qinv(fk)); // handle nq < np
    cczp_mul_ws(ws, zp_masked, tmp3, tmp3, tmp1);      // t = (sp * qinv) mod p_star
    ccn_setn(n, tmp2, nq, cczp_prime(zq));

    cczp_to_ws(ws, zp_masked, tmp3, tmp3);
    ccn_mul_ws(ws, n, tmp1, tmp2, tmp3);           // t = t * q
    ccn_addn(2 * n, r, tmp1, nq + SCA_MASK_N, sq); // r = t + sq

    CC_FREE_BP_WS(ws, bp);
}

CC_PURE cc_size CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(cc_size n)
{
    // cczp_n(p) + SCA_MASK_N
    cc_size nu = (n / 2 + 1) + SCA_MASK_N;

    return 2 * nu + (NB_MASK + 1) + cczp_nof_n(nu) +
       CC_MAX_EVAL(CCRSA_CRT_INIT_PQ_STAR_WORKSPACE_N(nu),
         CC_MAX_EVAL(CCRSA_CRT_EXP_MOD_PQ_STAR_WORKSPACE_N(nu),
           CC_MAX_EVAL(CCRSA_CRT_COMBINE_PQ_STAR_WORKSPACE_N(nu),
                       CCZP_MODN_WORKSPACE_N(n))
         )
       );
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_crt_power_blinded_ws(cc_ws_t ws,
                                      struct ccrng_state *blinding_rng,
                                      ccrsa_full_ctx_t fk,
                                      cc_unit *r,
                                      const cc_unit *x)
{

    cczp_t zm=ccrsa_ctx_zm(fk);
    cczp_t zp=ccrsa_ctx_private_zp(fk);
    cczp_t zq=ccrsa_ctx_private_zq(fk);
    const cc_unit *dp=ccrsa_ctx_private_dp(fk);
    const cc_unit *dq=ccrsa_ctx_private_dq(fk);
    cc_size nq=cczp_n(zq);
    cc_size np=cczp_n(zp);
    cc_size nu=np+SCA_MASK_N; // np >=nq, checked below
    int status=CCRSA_PRIVATE_OP_ERROR;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *rnd = CC_ALLOC_WS(ws, NB_MASK + 1);
    cc_unit *tmp = CC_ALLOC_WS(ws, nu * 2);
    cc_unit *sp  = tmp;
    cc_unit *sq  = tmp + nu;

    // Allocate a ZP which will be used to extend p and q for randomization
    cczp_t zu_masked = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(nu));

    cc_require_action((cczp_bitlen(zp) >= cczp_bitlen(zq)) && (np>=nq),
                      errOut,status=CCRSA_KEY_ERROR);      // Not supported here.
    cc_require_action(blinding_rng!=NULL,
                      errOut,status=CCRSA_INVALID_CONFIG); // Not supported here.

    // Random for masking
    CC_TEST_DISABLE_NESTED_DIT_CHECKS
    cc_require((status=ccn_random(NB_MASK + 1, rnd, blinding_rng))==0,errOut);
    CC_TEST_ENABLE_NESTED_DIT_CHECKS

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(rnd[NB_MASK]);

    // ------------ Step 1 ------------------
    // Modulus blinding:   q_star = rnd[0]*q
    // Exponent blinding: dq_star = dq + rnd[1]*(q-1)
    // Base blinding:     mq_star = (x + rnd[2]*q) Mod q_star

    // q_star = q * cstq
    status = ccrsa_crt_init_pq_star_ws(ws, zq, zu_masked, rnd[0]);
    cc_require(status == CCERR_OK, errOut);

    // sq = (x ^ dq) mod q_star
    ccrsa_crt_exp_mod_pq_star_ws(ws, zm, zq, zu_masked, x, dq, sq, &rnd[1]);

    // Modulus blinding:   p_star = rnd[3]*p
    // Exponent blinding: dp_star = dp + rnd[4]*(p-1)
    // Base blinding:     mp_star = (x + rnd[5]*p) Mod p_star

    // p_star = p * cstp
    status = ccrsa_crt_init_pq_star_ws(ws, zp, zu_masked, rnd[3]);
    cc_require(status == CCERR_OK, errOut);

    // sp = (x ^ dp) mod p_star
    ccrsa_crt_exp_mod_pq_star_ws(ws, zm, zp, zu_masked, x, dp, sp, &rnd[4]);

    // ------------ Step 2 ------------------
    // Garner recombination (requires 2*p>q, which is verified if |p|==|q|)
    //    with 0 < cstp,cstq < SCA_MASK
    //    pstar*(2*SCA_MASK) > q*SCA_MASK >= qstar
    //
    //    Values remain randomized as long as possible to protect all the operations
    //    tmp = (sp+(2*SCA_MASK)*p_star)-sq mod p_star
    //    tmp = tmp * qInv mod p_star
    //    tmp = tmp * q
    //    tmp = tmp + sq
    ccrsa_crt_combine_pq_star_ws(ws, fk, zu_masked, sp, sq, tmp);

    // r = tmp mod n
    cczp_modn_ws(ws, zm, r, 2 * nu, tmp);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccrsa_priv_crypt_blinded_ws(cc_ws_t ws,
                                struct ccrng_state *blinding_rng,
                                ccrsa_full_ctx_t fk,
                                cc_unit *out,
                                const cc_unit *in)
{
    CC_ASSERT_DIT_IS_ENABLED

    cc_size n = ccrsa_ctx_n(fk);
    cc_size np = cczp_n(ccrsa_ctx_private_zp(fk));
    cc_size nq = cczp_n(ccrsa_ctx_private_zq(fk));

    // Reject dp=1 or dq=1 as a valid key because e=1 is not acceptable.
    // by definition dp*e=1 mod (p-1) and dq*e=1 mod (p-1)
    if ((ccn_bitlen_internal(np, ccrsa_ctx_private_dp(fk)) <= 1)
        || (ccn_bitlen_internal(nq, ccrsa_ctx_private_dq(fk)) <= 1)
        || (ccn_bitlen_internal(n, ccrsa_ctx_e(fk)) <= 1)) {
        return CCRSA_KEY_ERROR;
    }

    // x >= m is not a valid input
    if (ccn_cmp_internal(n, in, ccrsa_ctx_m(fk)) >= 0) {
        return CCRSA_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    cc_unit *tmp_in = CC_ALLOC_WS(ws, n);
    ccn_set(n, tmp_in, in);

    // Compute out := in^d (mod m).
    int status = ccrsa_crt_power_blinded_ws(ws, blinding_rng, fk, out, in);

    // Verify that the computation is correct.
    (void)ccrsa_pub_crypt_ws(ws, ccrsa_ctx_public(fk), tmp, out);

    // status_cmp := (tmp != tmp_in) ? CCRSA_PRIVATE_OP_ERROR : 0
    int cmp = ccn_cmp_internal(n, tmp, tmp_in);
    int status_cmp = CCRSA_PRIVATE_OP_ERROR & cc_nonzero_mask_int(cmp);

    // status := status ? status : status_compare
    int status_mask = cc_nonzero_mask_int(status);
    status |= status_cmp & ~status_mask;

    // Clear output on error.
    // out := status ? 0xAAAAAA... : out
    cc_memset(tmp_in, 0xAA, ccn_sizeof_n(n));
    ccn_mux(n, status_mask & 1, out, tmp_in, out);

    CC_FREE_BP_WS(ws, bp);
    return status;
}
