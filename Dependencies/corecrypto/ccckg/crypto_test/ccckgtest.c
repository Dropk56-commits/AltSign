/* Copyright (c) (2019-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccckg.h>
#include "ccckg_internal.h"
#include "ccckg2_internal.h"

#include "cc_priv.h"
#include "testmore.h"

#include <corecrypto/ccsha2.h>

typedef ccec_const_cp_t (*cp_ptr)(void);
typedef const struct ccdigest_info* (*di_ptr)(void);

static void test_kat_v1(void)
{
    const uint8_t kat_s1[28] = {
        0x64, 0xf1, 0x1f, 0xea, 0xb6, 0xaa, 0x7b, 0x7f,
        0x36, 0x4c, 0x61, 0xc5, 0xba, 0x07, 0x5d, 0x31,
        0x9f, 0xb8, 0x16, 0x4b, 0x92, 0x54, 0x66, 0xfd,
        0x84, 0xef, 0xa9, 0x6c
    };
    const uint8_t kat_r1[32] = {
        0x27, 0x46, 0x75, 0xbd, 0x4d, 0xe5, 0xad, 0x5f,
        0xd2, 0xd4, 0xf8, 0x11, 0xb8, 0xd2, 0x4e, 0x6e,
        0x3a, 0x68, 0xcf, 0x7d, 0x82, 0x2c, 0x12, 0x45,
        0xb4, 0xea, 0x56, 0x62, 0x1b, 0x0a, 0x03, 0xf9
    };

    const uint8_t kat_s2[28] = {
        0x1b, 0x73, 0x2f, 0x46, 0xb9, 0x3c, 0x27, 0xb1,
        0x5f, 0xbe, 0x28, 0x5a, 0xe1, 0xcc, 0x39, 0x68,
        0x19, 0x06, 0x4a, 0xf1, 0x56, 0x54, 0x4d, 0x5e,
        0xfd, 0x2e, 0xdd, 0x1b
    };
    const uint8_t kat_r2[32] = {
        0xca, 0x49, 0x64, 0x84, 0xff, 0x33, 0x70, 0xeb,
        0x60, 0xd1, 0xa0, 0xb8, 0x3b, 0x2f, 0x78, 0x3d,
        0x0b, 0x51, 0x68, 0xed, 0xf7, 0xc9, 0xf8, 0x29,
        0x19, 0x6d, 0xc5, 0x18, 0x5b, 0xb0, 0x05, 0x34
    };

    const uint8_t kat_C1[32] = {
        0x08, 0x2f, 0x77, 0xa7, 0xdb, 0xc4, 0x4e, 0xf4,
        0x21, 0xfa, 0xd8, 0x64, 0xff, 0x56, 0x98, 0xe1,
        0xc1, 0x53, 0xb0, 0x42, 0xb0, 0x58, 0xdb, 0x66,
        0xde, 0x29, 0x63, 0x94, 0x7e, 0x52, 0x3f, 0x4a
    };
    const uint8_t kat_C2[1 + 28 * 2 + 32] = {
        0x04, 0x79, 0x29, 0x32, 0x7d, 0x23, 0x4a, 0x16,
        0x7b, 0xa7, 0xff, 0x1c, 0xfe, 0x4a, 0x7b, 0x9c,
        0x15, 0x6b, 0x1d, 0xb7, 0xa6, 0xb2, 0x81, 0x49,
        0x1c, 0x4e, 0x76, 0x94, 0x08, 0x8c, 0x9e, 0x4e,
        0x8f, 0x14, 0x57, 0xdb, 0xa7, 0x04, 0xf3, 0xbf,
        0x37, 0x86, 0xf0, 0x1d, 0x86, 0x92, 0x6a, 0xfa,
        0xc7, 0x26, 0xee, 0x48, 0xad, 0xa5, 0x46, 0x33,
        0xd0, 0xca, 0x49, 0x64, 0x84, 0xff, 0x33, 0x70,
        0xeb, 0x60, 0xd1, 0xa0, 0xb8, 0x3b, 0x2f, 0x78,
        0x3d, 0x0b, 0x51, 0x68, 0xed, 0xf7, 0xc9, 0xf8,
        0x29, 0x19, 0x6d, 0xc5, 0x18, 0x5b, 0xb0, 0x05,
        0x34
    };
    const uint8_t kat_C3[28 + 32] = {
        0x64, 0xf1, 0x1f, 0xea, 0xb6, 0xaa, 0x7b, 0x7f,
        0x36, 0x4c, 0x61, 0xc5, 0xba, 0x07, 0x5d, 0x31,
        0x9f, 0xb8, 0x16, 0x4b, 0x92, 0x54, 0x66, 0xfd,
        0x84, 0xef, 0xa9, 0x6c, 0x27, 0x46, 0x75, 0xbd,
        0x4d, 0xe5, 0xad, 0x5f, 0xd2, 0xd4, 0xf8, 0x11,
        0xb8, 0xd2, 0x4e, 0x6e, 0x3a, 0x68, 0xcf, 0x7d,
        0x82, 0x2c, 0x12, 0x45, 0xb4, 0xea, 0x56, 0x62,
        0x1b, 0x0a, 0x03, 0xf9
    };

    const uint8_t kat_P[1 + 28 * 2]  = {
        0x04, 0x9a, 0x9a, 0x57, 0x5d, 0x1e, 0x16, 0xe3,
        0x27, 0x74, 0xb2, 0xb3, 0x23, 0xf2, 0x20, 0x00,
        0x2b, 0x3d, 0x6f, 0x27, 0x2c, 0x20, 0x63, 0x70,
        0xe9, 0xeb, 0x8f, 0xe3, 0x06, 0x84, 0xd1, 0x97,
        0xac, 0xc5, 0x3f, 0x42, 0x5f, 0x11, 0xc0, 0xe6,
        0x9a, 0xc2, 0x7b, 0x87, 0x34, 0x8f, 0x89, 0xce,
        0x5b, 0xf5, 0x1a, 0x5a, 0x6e, 0x11, 0x3c, 0x4e,
        0xb9
    };
    const uint8_t kat_SK[32] = {
        0x2d, 0x34, 0x08, 0x4f, 0x11, 0x4f, 0x39, 0x52,
        0x3c, 0xb9, 0x62, 0x27, 0x1f, 0xba, 0xd2, 0x82,
        0xaa, 0xe9, 0x53, 0x57, 0xf3, 0xc3, 0x11, 0xac,
        0x75, 0x45, 0xb9, 0xa3, 0x97, 0xbc, 0x08, 0xe1
    };

    ccec_const_cp_t cp = ccec_cp_224();
    const struct ccdigest_info *di = ccsha256_di();
    struct ccrng_state *rng = global_test_rng;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_init(ctx_a, cp, di, rng);

    ccckg_ctx_decl(cp, di, ctx_b);
    ccckg_init(ctx_b, cp, di, rng);

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_ctx_init(cp, P_owner);

    // Set up contributor.
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg_ctx_s(ctx_a), sizeof(kat_s1), kat_s1);
    cc_memcpy(ccckg_ctx_r(ctx_a), kat_r1, sizeof(kat_r1));
    ccckg_ctx_state(ctx_a) = CCCKG_STATE_COMMIT;

    // Set up owner.
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg_ctx_s(ctx_b), sizeof(kat_s2), kat_s2);
    cc_memcpy(ccckg_ctx_r(ctx_b), kat_r2, sizeof(kat_r2));
    cc_memcpy(ccckg_ctx_c(ctx_b), kat_C1, sizeof(kat_C1));
    ccckg_ctx_state(ctx_b) = CCCKG_STATE_SHARE;

    // Finalize contributor.
    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    int rv = ccckg_contributor_finish(ctx_a, sizeof(kat_C2), kat_C2, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_OK, "ccckg_contributor_finish() failed");

    uint8_t buf[ccec_export_pub_size_cp(cp)];
    rv = ccec_export_pub(P_contrib, buf);
    is(rv, CCERR_OK, "ccec_export_pub() failed");

    ok_memcmp(opening, kat_C3, sizeof(kat_C3), "C3 invalid");
    ok_memcmp(sk_a, kat_SK, sizeof(kat_SK), "SK invalid");
    ok_memcmp(buf, kat_P, sizeof(kat_P), "P invalid");

    // Finalize owner.
    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_OK, "ccckg_owner_finish() failed");

    rv = ccec_export_pub(ccec_ctx_pub(P_owner), buf);
    is(rv, CCERR_OK, "ccec_export_pub() failed");

    ok_memcmp(sk_b, kat_SK, sizeof(kat_SK), "SK invalid");
    ok_memcmp(buf, kat_P, sizeof(kat_P), "P invalid");
}

static void test_kat_v2(void)
{
    const uint8_t kat_s1[28] = {
        0xe1, 0x73, 0x0a, 0x18, 0x0f, 0xf9, 0x67, 0x32,
        0xfc, 0x74, 0xed, 0x7d, 0x85, 0x84, 0x1e, 0xc6,
        0x5b, 0x6e, 0x04, 0x5d, 0xa8, 0x55, 0xfc, 0xcd,
        0x4d, 0xec, 0xa7, 0xdd
    };
    const uint8_t kat_r1[28] = {
        0x1f, 0x9b, 0x34, 0x76, 0x45, 0xe4, 0x2e, 0x3a,
        0x18, 0xa8, 0x17, 0xd4, 0xb2, 0xeb, 0xc5, 0xbb,
        0xf9, 0xf5, 0x7b, 0x08, 0x31, 0xd6, 0xad, 0x46,
        0xe0, 0x05, 0x84, 0x5a
    };
    const uint8_t kat_R1[1 + 28 * 2] = {
        0x04, 0x81, 0xb0, 0x2b, 0xdb, 0x0b, 0x9c, 0xc8,
        0x16, 0x5d, 0x09, 0xb3, 0xe3, 0xf1, 0xa5, 0x97,
        0x14, 0xcd, 0x1d, 0x34, 0x34, 0xe6, 0x31, 0x06,
        0x66, 0x29, 0x65, 0xfb, 0x68, 0xea, 0x08, 0x06,
        0x30, 0xfb, 0x0c, 0x06, 0x7d, 0x8c, 0x35, 0x96,
        0x01, 0xbb, 0xaf, 0xc4, 0x92, 0x81, 0x6f, 0xd6,
        0x9d, 0xf4, 0xc9, 0x0e, 0x26, 0x09, 0xfb, 0x51,
        0x0a
    };

    const uint8_t kat_s2[28] = {
        0x09, 0x83, 0x78, 0xda, 0x2e, 0x5a, 0x51, 0x57,
        0xf6, 0xd7, 0x0f, 0x95, 0xfb, 0xb7, 0x76, 0x14,
        0x00, 0x9a, 0x81, 0xb6, 0x9c, 0xe7, 0x14, 0x6d,
        0xb4, 0xc4, 0xe9, 0xb9
    };
    const uint8_t kat_r2[28] = {
        0x3e, 0x17, 0xb0, 0x46, 0x8d, 0x2a, 0xa2, 0xdb,
        0xb5, 0x2f, 0x7e, 0x8d, 0x22, 0xc3, 0xf8, 0x83,
        0x2a, 0x9d, 0x07, 0x00, 0xda, 0x6f, 0x00, 0x5c,
        0xfa, 0x2d, 0x14, 0x47
    };

    const uint8_t kat_C1[32] = {
        0x00, 0x6f, 0x66, 0x84, 0xdf, 0x92, 0x86, 0x95,
        0x47, 0x04, 0x83, 0xf9, 0xe5, 0x1b, 0x02, 0x18,
        0xe7, 0x16, 0xba, 0xfa, 0x1d, 0xbe, 0xdc, 0xed,
        0x55, 0x4f, 0x02, 0x40, 0xf1, 0x4c, 0x16, 0x97
    };
    const uint8_t kat_C2[(1 + 28 * 2) * 2] = {
        0x04, 0xa1, 0xc2, 0x54, 0x01, 0x7a, 0xb6, 0x29,
        0x9d, 0x59, 0x22, 0xee, 0x39, 0xa0, 0x88, 0x7e,
        0x23, 0x4e, 0x03, 0x74, 0x1b, 0x1f, 0xb6, 0x13,
        0x8d, 0x1a, 0xf3, 0x49, 0x65, 0xa3, 0xf7, 0x91,
        0xbb, 0xe7, 0x76, 0x5e, 0x8f, 0x1b, 0x20, 0x66,
        0xd5, 0x2b, 0x12, 0x56, 0xf1, 0x9b, 0x30, 0xd4,
        0x86, 0x94, 0x8e, 0x4c, 0x0f, 0xef, 0x96, 0x42,
        0xaa, 0x04, 0x00, 0x58, 0xbc, 0x7b, 0x47, 0x1a,
        0xb9, 0xe7, 0x2a, 0x65, 0xd8, 0x32, 0x27, 0xdf,
        0x91, 0xbf, 0x48, 0xed, 0xd4, 0xc6, 0x74, 0x0f,
        0xdb, 0x5a, 0x5c, 0xde, 0x87, 0x27, 0x30, 0xdd,
        0xc5, 0x19, 0xac, 0xf1, 0x68, 0xae, 0xcb, 0x12,
        0xbb, 0x90, 0x65, 0x65, 0x67, 0x04, 0xc6, 0x18,
        0x3f, 0x62, 0x44, 0xd7, 0x62, 0xe3, 0xc8, 0xfd,
        0xa8, 0xaf
    };
    const uint8_t kat_C3[28 + 1 + 28 * 2] = {
        0xe1, 0x73, 0x0a, 0x18, 0x0f, 0xf9, 0x67, 0x32,
        0xfc, 0x74, 0xed, 0x7d, 0x85, 0x84, 0x1e, 0xc6,
        0x5b, 0x6e, 0x04, 0x5d, 0xa8, 0x55, 0xfc, 0xcd,
        0x4d, 0xec, 0xa7, 0xdd, 0x04, 0x81, 0xb0, 0x2b,
        0xdb, 0x0b, 0x9c, 0xc8, 0x16, 0x5d, 0x09, 0xb3,
        0xe3, 0xf1, 0xa5, 0x97, 0x14, 0xcd, 0x1d, 0x34,
        0x34, 0xe6, 0x31, 0x06, 0x66, 0x29, 0x65, 0xfb,
        0x68, 0xea, 0x08, 0x06, 0x30, 0xfb, 0x0c, 0x06,
        0x7d, 0x8c, 0x35, 0x96, 0x01, 0xbb, 0xaf, 0xc4,
        0x92, 0x81, 0x6f, 0xd6, 0x9d, 0xf4, 0xc9, 0x0e,
        0x26, 0x09, 0xfb, 0x51, 0x0a
    };

    const uint8_t kat_P[1 + 28 * 2]  = {
        0x04, 0x73, 0x6b, 0xeb, 0x2d, 0xd1, 0x5f, 0x2e,
        0x5f, 0xfc, 0x52, 0x20, 0xda, 0x57, 0x2f, 0x6e,
        0xd6, 0x17, 0x6e, 0x5a, 0xa4, 0x31, 0xe3, 0xc5,
        0x0b, 0x6c, 0x7f, 0x57, 0x2e, 0x2b, 0x40, 0xa0,
        0x68, 0x4d, 0x1b, 0x20, 0xff, 0x13, 0x7c, 0xbf,
        0xbf, 0x7d, 0x1e, 0xa0, 0xa4, 0x0f, 0x9c, 0x55,
        0x6c, 0xa4, 0xb2, 0x85, 0x7e, 0xe1, 0x22, 0xd5,
        0xc6
    };
    const uint8_t kat_SK[32] = {
        0x9f, 0x98, 0xd4, 0x4e, 0x0e, 0x20, 0xc4, 0xbb,
        0x46, 0x68, 0x8e, 0x45, 0x64, 0x85, 0xee, 0x85,
        0xc8, 0xb7, 0x03, 0x79, 0x1c, 0x52, 0xcd, 0x85,
        0xc6, 0x05, 0x1e, 0x26, 0xe0, 0x1a, 0xfe, 0xcb
    };

    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_a);
    int rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    ccckg2_ctx_decl(params, ctx_b);
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_ctx_init(cp, P_owner);

    // Set up contributor.
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg2_ctx_s(ctx_a), sizeof(kat_s1), kat_s1);
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg2_ctx_r(ctx_a), sizeof(kat_r1), kat_r1);
    cc_memcpy(ccckg2_ctx_rG(ctx_a), kat_R1, sizeof(kat_R1));
    ccckg_ctx_state(ctx_a) = CCCKG_STATE_COMMIT;

    // Set up owner.
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg2_ctx_s(ctx_b), sizeof(kat_s2), kat_s2);
    (void)ccn_read_uint(ccec_cp_n(cp), ccckg2_ctx_r(ctx_b), sizeof(kat_r2), kat_r2);
    cc_memcpy(ccckg2_ctx_c(ctx_b), kat_C1, sizeof(kat_C1));
    ccckg_ctx_state(ctx_b) = CCCKG_STATE_SHARE;

    // Finalize contributor.
    uint8_t sk_a[32];
    uint8_t opening[ccckg2_sizeof_opening(params)];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(kat_C2), kat_C2, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_finish() failed");

    uint8_t buf[ccec_export_pub_size_cp(cp)];
    rv = ccec_export_pub(P_contrib, buf);
    is(rv, CCERR_OK, "ccec_export_pub() failed");

    ok_memcmp(opening, kat_C3, sizeof(kat_C3), "C3 invalid");
    ok_memcmp(sk_a, kat_SK, sizeof(kat_SK), "SK invalid");
    ok_memcmp(buf, kat_P, sizeof(kat_P), "P invalid");

    // Finalize owner.
    uint8_t sk_b[32];
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_OK, "ccckg2_owner_finish() failed");

    rv = ccec_export_pub(ccec_ctx_pub(P_owner), buf);
    is(rv, CCERR_OK, "ccec_export_pub() failed");

    ok_memcmp(sk_b, kat_SK, sizeof(kat_SK), "SK invalid");
    ok_memcmp(buf, kat_P, sizeof(kat_P), "P invalid");
}

static int test_full_run_v1(cp_ptr _cp, di_ptr _di)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = _di();
    ccec_const_cp_t cp = _cp();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_full_run_v2(cp_ptr _cp, di_ptr _di)
{
    struct ccrng_state *rng = global_test_rng;
    ccec_const_cp_t cp = _cp();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    const struct ccckg2_params params = {
        .version = CCCKG_VERSION_2, .cp = _cp, .di = _di
    };

    ccckg2_ctx_decl(&params, ctx_a);
    ccckg2_ctx_decl(&params, ctx_b);

    rv = ccckg2_init(ctx_a, &params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, &params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(&params)];
    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_commit() failed");

    uint8_t share[ccckg2_sizeof_share(&params)];
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    uint8_t sk_a[32];
    uint8_t opening[ccckg2_sizeof_opening(&params)];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_finish() failed");

    uint8_t sk_b[32];
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_OK, "ccckg2_owner_finish() failed");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg2_ctx_clear(&params, ctx_a);
    ccckg2_ctx_clear(&params, ctx_b);

    return 0;
}

static int test_bogus_inputs_v1(void)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();
    ccec_const_cp_t cp = ccec_cp_224();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_full_ctx_decl_cp(ccec_cp_384(), P_bogus_full);
    ccec_pub_ctx_decl_cp(ccec_cp_384(), P_bogus);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];

    // Passing the wrong commitment size must fail.
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment) + 1, commitment);
    is(rv, CCERR_PARAMETER, "Generated commitment");

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];

    // Passing the wrong commitment size must fail.
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment) + 1, commitment, sizeof(share), share);
    is(rv, CCERR_PARAMETER, "ccckg_owner_generate_share should fail");

    // Passing the wrong share size must fail.
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share) + 1, share);
    is(rv, CCERR_PARAMETER, "ccckg_owner_generate_share should fail");

    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32], sk_b[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];

    // Passing the wrong share size must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share) + 1, share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_PARAMETER, "ccckg_contributor_finish should fail");

    // Passing the wrong opening size must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening) + 1, opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_PARAMETER, "ccckg_contributor_finish should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_bogus, sizeof(sk_a), sk_a);
    isnt(rv, CCERR_OK, "ccckg_contributor_finish should fail");

    // Passing a share with the wrong format must fail.
    share[0] = 0x02;
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, CCERR_OK, "ccckg_contributor_finish should fail");

    share[0] = 0x04;
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    // Passing the wrong opening size must fail.
    rv = ccckg_owner_finish(ctx_b, sizeof(opening) + 1, opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "ccckg_owner_finish should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_bogus_full, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "ccckg_owner_finish should fail");

    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_inputs_v2(void)
{
    struct ccrng_state *rng = global_test_rng;
    ccec_const_cp_t cp = ccec_cp_224();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_full_ctx_decl_cp(ccec_cp_384(), P_bogus_full);
    ccec_pub_ctx_decl_cp(ccec_cp_384(), P_bogus);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_a);
    ccckg2_ctx_decl(params, ctx_b);

    const struct ccckg2_params bogus_params = {
        .version = CCCKG_VERSION_1,
        .cp = ccec_cp_224,
        .di = ccsha256_di
    };

    rv = ccckg2_init(ctx_a, &bogus_params);
    is(rv, CCERR_PARAMETER, "ccckg2_init() should fail");
    rv = ccckg2_init(ctx_b, &bogus_params);
    is(rv, CCERR_PARAMETER, "ccckg2_init() should fail");

    rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(params)];

    // Passing the wrong commitment size must fail.
    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment) + 1, commitment, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_contributor_commit() should fail");

    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_commit() failed");

    uint8_t share[ccckg2_sizeof_share(params)];

    // Passing the wrong commitment size must fail.
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment) + 1, commitment, sizeof(share), share, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_owner_generate_share() should fail");

    // Passing the wrong share size must fail.
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share) + 1, share, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_owner_generate_share() should fail");

    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    uint8_t sk_a[32], sk_b[32];
    uint8_t opening[ccckg2_sizeof_opening(params)];

    // Passing the wrong share size must fail.
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share) + 1, share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_contributor_finish() should fail");

    // Passing the wrong opening size must fail.
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening) + 1, opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_contributor_finish() should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_bogus, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Passing a share with the wrong format must fail.
    share[0] = 0x02;
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    share[0] = 0x04;
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_finish() failed");

    // Passing the wrong opening size must fail.
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening) + 1, opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_owner_finish() should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_bogus_full, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_PARAMETER, "ccckg2_owner_finish() should fail");

    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_OK, "ccckg2_owner_finish() failed");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg2_ctx_clear(params, ctx_a);
    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

static int test_bogus_commitment_v1(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    // Corrupt the commitment.
    commitment[0] ^= 0x01;

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_INTEGRITY, "Invalid commitment");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_commitment_v2(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg2_ctx_decl(params, ctx_a);
    ccckg2_ctx_decl(params, ctx_b);

    rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(params)];
    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "Generated commitment");

    // Corrupt the commitment.
    commitment[0] ^= 0x01;

    uint8_t share[ccckg2_sizeof_share(params)];
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    uint8_t sk_a[32];
    uint8_t opening[ccckg2_sizeof_opening(params)];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_finish() failed");

    uint8_t sk_b[32];
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_INTEGRITY, "ccckg2_owner_finish() failed");

    ccckg2_ctx_clear(params, ctx_a);
    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

static int test_bogus_scalar_v1(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_ctx_init(cp, P_owner);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_b);
    ccckg_init(ctx_b, cp, di, rng);

    // Assemble commitment data with an invalid scalar.
    uint8_t commitment_data[ccckg_sizeof_opening(cp, di)];
    ccn_write_uint_padded(ccec_cp_n(cp), cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp), commitment_data);

    // Build the commitment.
    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    ccdigest(di, sizeof(commitment_data), commitment_data, commitment);

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(commitment_data), commitment_data, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "Invalid scalar");

    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_scalar_v2(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_ctx_init(cp, P_owner);

    int rv;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_b);
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    // Assemble commitment data with an invalid scalar.
    uint8_t commitment_data[ccckg2_sizeof_opening(params)];
    ccn_write_uint_padded(ccec_cp_n(cp), cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp), commitment_data);

    // Build the commitment.
    uint8_t commitment[ccckg2_sizeof_commitment(params)];
    ccdigest(di, sizeof(commitment_data), commitment_data, commitment);

    uint8_t share[ccckg2_sizeof_share(params)];
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "Generated share");

    uint8_t sk_b[32];
    rv = ccckg2_owner_finish(ctx_b, sizeof(commitment_data), commitment_data, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_PARAMETER, "Invalid scalar");

    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

static int test_bogus_share_v1(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    // Corrupt S' encoding.
    share[0] = 0x03;

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, 0, "Invalid share");

    // Corrupt S'.
    share[0] = 0x04;
    share[ccec_export_pub_size_cp(cp) - 1] ^= 0x55;

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, 0, "Invalid share");

    // Turn S' into the point at infinity.
    cc_clear(ccec_export_pub_size_cp(cp) - 1, share + 1);

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, 0, "Invalid share");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_share_v2(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_a);
    ccckg2_ctx_decl(params, ctx_b);

    rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(params)];
    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_commit() failed");

    uint8_t share[ccckg2_sizeof_share(params)];
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    // Make a copy of the share.
    uint8_t share2[ccckg2_sizeof_share(params)];
    cc_memcpy(share2, share, sizeof(share));

    // Corrupt S' encoding.
    share[0] = 0x03;

    uint8_t sk_a[32];
    uint8_t opening[ccckg2_sizeof_opening(params)];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Corrupt S'.
    share[0] = 0x04;
    share[ccec_export_pub_size_cp(cp) - 1] ^= 0x55;

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Turn S' into the point at infinity.
    cc_clear(ccec_export_pub_size_cp(cp) - 1, share + 1);

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Corrupt R' encoding.
    share2[ccec_export_pub_size_cp(cp)] = 0x03;

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share2), share2, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Corrupt R'.
    share2[ccec_export_pub_size_cp(cp)] = 0x04;
    share2[2 * ccec_export_pub_size_cp(cp) - 1] ^= 0x55;

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share2), share2, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    // Turn R' into the point at infinity.
    cc_clear(ccec_export_pub_size_cp(cp) - 1, share2 + ccec_export_pub_size_cp(cp) + 1);

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share2), share2, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    isnt(rv, CCERR_OK, "ccckg2_contributor_finish() should fail");

    ccckg2_ctx_clear(params, ctx_a);
    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

static int test_bogus_opening_v1(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    // Corrupt the opening.
    opening[0] ^= 0x01;

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_INTEGRITY, "Invalid commitment");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_opening_v2(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_a);
    ccckg2_ctx_decl(params, ctx_b);

    rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(params)];
    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_commit() failed");

    uint8_t share[ccckg2_sizeof_share(params)];
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    uint8_t sk_a[32];
    uint8_t opening[ccckg2_sizeof_opening(params)];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_finish() failed");

    // Corrupt the opening.
    opening[0] ^= 0x01;

    uint8_t sk_b[32];
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_INTEGRITY, "ccckg2_owner_finish() failed");

    ccckg2_ctx_clear(params, ctx_a);
    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

static int test_state_machine_v1(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    uint8_t share[ccckg_sizeof_share(cp, di)];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];

    // A=STATE_INIT, B=STATE_INIT

    uint8_t sk_a[32], sk_b[32];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    // A=STATE_COMMIT, B=STATE_SHARE

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    // A=STATE_FINISH, B=STATE_FINISH

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_state_machine_v2(void)
{
    ccec_const_cp_t cp = ccec_cp_224();
    struct ccrng_state *rng = global_test_rng;

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg2_params_t params = ccckg2_params_p224_sha256_v2();

    ccckg2_ctx_decl(params, ctx_a);
    ccckg2_ctx_decl(params, ctx_b);

    rv = ccckg2_init(ctx_a, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");
    rv = ccckg2_init(ctx_b, params);
    is(rv, CCERR_OK, "ccckg2_init() failed");

    uint8_t commitment[ccckg2_sizeof_commitment(params)];
    uint8_t share[ccckg2_sizeof_share(params)];
    uint8_t opening[ccckg2_sizeof_opening(params)];

    // A=STATE_INIT, B=STATE_INIT

    uint8_t sk_a[32], sk_b[32];
    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");

    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_OK, "ccckg2_contributor_commit() failed");
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_OK, "ccckg2_owner_generate_share() failed");

    // A=STATE_COMMIT, B=STATE_SHARE

    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, 0, "ccckg2_contributor_finish() failed");
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, 0, "ccckg2_owner_finish() failed");

    // A=STATE_FINISH, B=STATE_FINISH

    rv = ccckg2_contributor_commit(ctx_a, sizeof(commitment), commitment, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg2_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg2_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");
    rv = ccckg2_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b, rng);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg2_ctx_clear(params, ctx_a);
    ccckg2_ctx_clear(params, ctx_b);

    return 0;
}

int ccckg_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    cp_ptr curves[] = { ccec_cp_192, ccec_cp_224, ccec_cp_256, ccec_cp_384, ccec_cp_521 };
    di_ptr hashes[] = { ccsha256_di, ccsha384_di, ccsha512_di };

    int num_tests = 0;
    num_tests += 16; // full run tests
    num_tests *= CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(hashes);
    num_tests += 9;  // v1 kat tests
    num_tests += 11; // v2 kat tests
    num_tests += 34; // bogus inputs
    num_tests += 12; // bogus commitment
    num_tests += 7;  // bogus scalar
    num_tests += 19; // bogus shares
    num_tests += 12; // bogus opening
    num_tests += 32; // state machine
    plan_tests(num_tests);

    test_kat_v1();
    test_kat_v2();

    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        cp_ptr cp = curves[i];

        for (size_t j = 0; j < CC_ARRAY_LEN(hashes); j++) {
            di_ptr di = hashes[j];

            is(test_full_run_v1(cp, di), 0, "Full run test");
            is(test_full_run_v2(cp, di), 0, "Full run test");
        }
    }

    is(test_bogus_inputs_v1(), 0, "Bogus input test");
    is(test_bogus_inputs_v2(), 0, "Bogus input test");
    is(test_bogus_commitment_v1(), 0, "Bogus commitment test");
    is(test_bogus_commitment_v2(), 0, "Bogus commitment test");
    is(test_bogus_scalar_v1(), 0, "Bogus scalar test");
    is(test_bogus_scalar_v2(), 0, "Bogus scalar test");
    is(test_bogus_share_v1(), 0, "Bogus share test");
    is(test_bogus_share_v2(), 0, "Bogus share test");
    is(test_bogus_opening_v1(), 0, "Bogus opening test");
    is(test_bogus_opening_v2(), 0, "Bogus opening test");
    is(test_state_machine_v1(), 0, "State machine test");
    is(test_state_machine_v2(), 0, "State machine test");

    return 0;
}
