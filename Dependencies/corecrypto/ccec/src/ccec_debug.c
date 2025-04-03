/* Copyright (c) (2010-2012,2014-2019,2021,2024) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "cc_debug.h"
#include "ccec_internal.h"

// CC_UNUSED on all the parameters because cc_printf is defined empty for some targets.

void ccec_alprint(CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED ccec_const_affine_point_t s) {
    cc_printf("%s { x -> ", label);
    ccn_print(ccec_cp_n(cp), ccec_const_point_x(s, cp));
    cc_printf(", y -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_y(s, cp));
    cc_printf("}\n");
}

void ccec_plprint(CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED ccec_const_projective_point_t s) {
    cc_printf("%s { x -> ", label);
    ccn_print(ccec_cp_n(cp), ccec_const_point_x(s, cp));
    cc_printf(", y -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_y(s, cp));
    cc_printf(", z -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_z(s, cp));
    cc_printf("}\n");
}

void ccec_print_full_key(CC_UNUSED const char *label, CC_UNUSED ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    cc_printf("full key %s { \n", label);
    ccec_plprint(ccec_ctx_cp(key), "pubkey:", ccec_ctx_point(key));
    cc_printf("priv: {");
    ccn_print(ccec_cp_n(ccec_ctx_cp(key)), ccec_ctx_k(key));
    cc_printf("}\n");
}

void ccec_print_public_key(CC_UNUSED const char *label, CC_UNUSED ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED_WITH_SB

    cc_printf("public key ");
    ccec_plprint(ccec_ctx_cp(key), label, ccec_ctx_point(key));
}


void ccec_print_sig(CC_UNUSED const char *label, CC_UNUSED size_t count, CC_UNUSED const uint8_t *s) {
    cc_printf("%s { %zu, ",label, count);
    for (size_t ix = count; ix--;) {
        cc_printf("%.02x", s[ix]);
    }
    cc_printf("\n");
}

void ccec_print_cp(CC_UNUSED ccec_const_cp_t cp)
{
    ccec_print_scalar(cp, "p", ccec_cp_p(cp));
    cc_printf("Fp = GF(p)\na = -3\n");
    ccec_print_scalar(cp, "b", ccec_cp_b(cp));
    cc_printf("b = lift(Fp(b / 2^%u))\n", (unsigned)(ccec_ccn_size(cp) * 8));
    ccec_print_scalar(cp, "q", cczp_prime(ccec_cp_zq(cp)));
    cc_printf("Fq = GF(q)\nEC = EllipticCurve([Fp(a), Fp(b)])\nEC.set_order(q)\n");
    ccec_print_affine_point(cp, "G", ccec_cp_g(cp));
}

void ccec_print_scalar(CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED cc_unit const* scalar) {
    cc_printf("%s = 0x", label);
    ccn_print(ccec_cp_n(cp), scalar);
    cc_printf("\n");
}

void ccec_print_affine_point(CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED ccec_const_affine_point_t p)
{
    cc_printf("%s = EC(Fp(0x", label);
    ccn_print(ccec_cp_n(cp), ccec_const_point_x(p, cp));
    cc_printf("), Fp(0x");
    ccn_print(ccec_cp_n(cp), ccec_const_point_y(p, cp));
    cc_printf("))\n");
}

void ccec_print_projective_point_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED ccec_const_projective_point_t p)
{
    cc_size n = ccec_cp_n(cp);
    CC_DECL_BP_WS(ws, bp);
    if (ccec_is_point_at_infinity(cp, p)) {
        cc_printf("%s = EC(0)\n", label);
    } else {
        ccec_affine_point_t affine = (ccec_affine_point_t) CCEC_ALLOC_POINT_WS(ws, n);
        (void)ccec_affinify_ws(ws, cp, affine, p);
        ccec_print_affine_point(cp, label, affine);
    }
    CC_FREE_BP_WS(ws, bp);
}

void ccec_print_projective_point(CC_UNUSED ccec_const_cp_t cp, CC_UNUSED const char *label, CC_UNUSED ccec_const_projective_point_t p)
{
    cc_size n = ccec_cp_n(cp);
    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCEC_PRINT_PROJECTIVE_POINT_WORKSPACE_N(n), rv);
    if (!rv) ccec_print_projective_point_ws(ws, cp, label, p);
    CC_FREE_WORKSPACE(ws);
}

