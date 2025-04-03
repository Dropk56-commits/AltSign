/* Copyright (c) (2012,2015-2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

#define mask_msb (CC_UNIT_C(1) << (CCN_UNIT_BITS - 1))

#define mask_hi (CCN_UNIT_MASK << (CCN_UNIT_HALF_BITS - 1))
#define mask_lo (CCN_UNIT_LOWER_HALF_MASK >> 1)

CC_INLINE
void CC_MAYBE_SWAP(cc_unit m, cc_unit *a, cc_unit *b)
{
    cc_assert((-m >> 1) == 0);
    cc_unit t;
    cc_mux_mask(t, m, *b, *a);
    *b ^= *a ^ t;
    *a = t;
}

/*
 * Updates either a or b, using update factors f and g.
 *
 * This is called after every k-1 iterations of the main loop, where k is half
 * the architecture's word size.
 *
 * The update factors f and g allow computing the actual value of either a or
 * b after k-1 iterations with only approximations of u and v.
 *
 * Computes a * f + b * g (mod p).
 */
static void cczp_inv_update_redc_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a, cc_unit f, const cc_unit *b, cc_unit g)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t0 = CC_ALLOC_WS(ws, n + 1);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);

    // f,g < 0?
    cc_unit f_lt_z = cc_bit_to_mask_cc_unit(f >> (CCN_UNIT_BITS - 1));
    cc_unit g_lt_z = cc_bit_to_mask_cc_unit(g >> (CCN_UNIT_BITS - 1));

    // In two's complement multiplication, the multiplier has to be
    // non-negative. If f < 0, negate f and a.
    cczp_cond_negate(zp, -f_lt_z, t0, a);
    cc_mux_mask(f, f_lt_z, -f, f);

    // If g < 0, negate g and b.
    cczp_cond_negate(zp, -g_lt_z, t1, b);
    cc_mux_mask(g, g_lt_z, -g, g);

    // u = u * f + v * g
    t0[n] = ccn_mul1(n, t0, t0, f);
    t0[n] += ccn_addmul1(n, t0, t1, g);

    // Montgomery REDC to divide by 2^(CCN_UNIT_HALF_BITS - 1).
    t0[n] += ccn_addmul1(n, t0, cczp_prime(zp), (t0[0] * cczp_p0inv(zp)) & mask_lo);
    ccn_shift_right(n + 1, t0, t0, CCN_UNIT_HALF_BITS - 1);
    ccn_set(n, r, t0);

    // Optional final reduction.
    cc_unit borrow = ccn_subn(n + 1, t0, t0, n, cczp_prime(zp));
    ccn_mux(n, borrow, r, r, t0);

    // Invariant.
    cc_assert(ccn_cmp_public_value(n, r, cczp_prime(zp)) < 0);

    CC_FREE_BP_WS(ws, bp);
}

int cczp_inv_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    size_t iterations = ccn_bitsof_n(2 * n);

    if (ccn_cmp_internal(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    cczp_from_ws(ws, zp, u, x);
    ccn_set(n, v, cczp_prime(zp));

    cc_unit *a = CC_ALLOC_WS(ws, n);
    cc_unit *b = CC_ALLOC_WS(ws, n);

    ccn_seti(n, a, 1);
    ccn_clear(n, b);

    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    for (size_t i = 0; i < cc_ceiling(iterations, CCN_UNIT_HALF_BITS - 1); i++) {
        cc_unit ua, va;

        // Compute word-size approximations of u and v.
        ccn_gcd_approximate(n, u, &ua, v, &va);

#if CORECRYPTO_DEBUG
        {
            // abits = max(len(u), len(v), 2k)
            size_t abits = CC_MAX(ccn_bitlen_internal(n, u), ccn_bitlen_internal(n, v));
            abits = CC_MAX(abits, CCN_UNIT_BITS);

            // Check the approximation of u against the computed value.
            ccn_shift_right_multi(n, tmp, u, abits - CCN_UNIT_BITS);
            cc_assert(ua == ((tmp[0] & mask_hi) | (u[0] & mask_lo)));

            // Check the approximation of v against the computed value.
            ccn_shift_right_multi(n, tmp, v, abits - CCN_UNIT_BITS);
            cc_assert(va == ((tmp[0] & mask_hi) | (v[0] & mask_lo)));
        }
#endif

        // These are the update factors that we'll use to reconstruct the
        // correct values for u and v, after using only their approximations
        // in the inner loop. These factors basically keep track of the
        // operations that are usually performed on u and v directly.
        cc_unit f0 = CC_UNIT_C(1) << (CCN_UNIT_HALF_BITS - 1);
        cc_unit g1 = CC_UNIT_C(1) << (CCN_UNIT_HALF_BITS - 1);
        cc_unit f1 = 0, g0 = 0;

        for (size_t j = 0; j < CCN_UNIT_HALF_BITS - 1; j++) {
            // if u is even, u /= 2
            cc_unit m_odd = cc_bit_to_mask_cc_unit(ua & 1);
            ua >>= m_odd + 1;

            cc_unit u_lt_v = cc_smaller_mask_cc_unit(ua, va);

            // if u < v, (u,v,f0,g0,f1,g1) = (v,u,f1,g1,f0,g0)
            CC_MAYBE_SWAP(u_lt_v & m_odd, &ua, &va);
            CC_MAYBE_SWAP(u_lt_v & m_odd, &f0, &f1);
            CC_MAYBE_SWAP(u_lt_v & m_odd, &g0, &g1);

            // u = u - v / 2
            ua -= va & m_odd;
            ua >>= -m_odd;

            // (f0, g0) = (f0 - f1, g0 - g1)
            f0 -= f1 & m_odd;
            g0 -= g1 & m_odd;

            // Arithmetic right shift of signed f0,g0.
            f0 = (f0 & mask_msb) | (f0 >> 1);
            g0 = (g0 & mask_msb) | (g0 >> 1);
        }

        // u = |f0 * u + g0 * v| >> CCN_UNIT_HALF_BITS-1
        cc_unit neg_a = ccn_gcd_update_ws(ws, n, tmp, u, f0, v, g0);
        // v = |f1 * u + g1 * v| >> CCN_UNIT_HALF_BITS-1
        cc_unit neg_b = ccn_gcd_update_ws(ws, n, v, u, f1, v, g1);

        ccn_set(n, u, tmp);

        // if a was < 0, (f0,g0) = (-f0,-g0)
        cc_unit ma = cc_bit_to_mask_cc_unit(neg_a);
        cc_mux_mask(f0, ma, -f0, f0);
        cc_mux_mask(g0, ma, -g0, g0);

        // if b was < 0, (f1,g1) = (-f1,-g1)
        cc_unit mb = cc_bit_to_mask_cc_unit(neg_b);
        cc_mux_mask(f1, mb, -f1, f1);
        cc_mux_mask(g1, mb, -g1, g1);

        // a = |f0 * a + g0 * b| >> CCN_UNIT_HALF_BITS-1 (mod p)
        cczp_inv_update_redc_ws(ws, zp, tmp, a, f0, b, g0);
        // b = |f1 * a + g1 * b| >> CCN_UNIT_HALF_BITS-1 (mod p)
        cczp_inv_update_redc_ws(ws, zp, b, a, f1, b, g1);

        ccn_set(n, a, tmp);
    }

    cc_assert(ccn_is_zero(n, u));

    int rv;

    if (ccn_is_one(n, v)) {
        rv = CCERR_OK;
        cczp_to_ws(ws, zp, r, b);
    } else {
        rv = CCERR_PARAMETER;
        ccn_clear(n, r);
    }

    CC_FREE_BP_WS(ws, bp);

    return rv;
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, cczp_inv_default_ws)

int cczp_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return CCZP_FUNCS_GET(zp, cczp_inv)(ws, zp, r, x);
}

int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INV_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_inv_ws(ws, zp, r, x);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
