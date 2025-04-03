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

#include <corecrypto/cc_config.h>

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cckyber.h>
#include <corecrypto/ccaes.h>
#include "cckem_internal.h"

#include "testmore.h"

static void cckem_encapsulate_decapsulate(const struct cckem_info *info)
{
    size_t ciphertext_nbytes = cckem_encapsulated_key_nbytes_info(info);
    size_t sharedsecret_nbytes = cckem_shared_key_nbytes_info(info);

    uint8_t ciphertext[ciphertext_nbytes];
    uint8_t sharedsecret_encapsulate[sharedsecret_nbytes];
    uint8_t sharedsecret_decapsulate[sharedsecret_nbytes];

    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);
    cckem_pub_ctx_t pubctx = cckem_public_ctx(ctx);

    is(cckem_generate_key(ctx, global_test_rng), CCERR_OK, "cckem_generate_key failure");
    is(cckem_encapsulate(pubctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_encapsulate, global_test_rng),
       CCERR_OK,
       "cckem_encapsulate: Encapsulation error");
    is(cckem_decapsulate(ctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_decapsulate), CCERR_OK, "cckem_decapsulate: Decapsulation error");
    ok_memcmp(sharedsecret_encapsulate, sharedsecret_decapsulate, sharedsecret_nbytes, "Shared secret invalid");

    // Ensure input validation for Encapsulation.
    cckem_ctx_pubkey(pubctx)[0] |= 0xff;
    cckem_ctx_pubkey(pubctx)[1] |= 0xff;

    is(cckem_encapsulate(pubctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_encapsulate, global_test_rng),
       CCERR_PARAMETER,
       "cckem_encapsulate: Encapsulation should fail");
}

static void cckem_export_import(const struct cckem_info *info)
{
    size_t ciphertext_nbytes = cckem_encapsulated_key_nbytes_info(info);
    size_t sharedsecret_nbytes = cckem_shared_key_nbytes_info(info);
    size_t pubkey_nbytes = cckem_pubkey_nbytes_info(info);
    size_t privkey_nbytes = cckem_privkey_nbytes_info(info);

    uint8_t ciphertext[ciphertext_nbytes];
    uint8_t sharedsecret_encapsulate[sharedsecret_nbytes];
    uint8_t sharedsecret_decapsulate[sharedsecret_nbytes];
    uint8_t exported_pubkey[pubkey_nbytes];
    uint8_t exported_privkey[privkey_nbytes];
    
    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);
    cckem_pub_ctx_t pubctx = cckem_public_ctx(ctx);
    
    cckem_pub_ctx_decl(info, exported_pub_ctx);
    cckem_full_ctx_decl(info, exported_priv_ctx);
    
    is(cckem_generate_key(ctx, global_test_rng), CCERR_OK, "cckem_generate_key failure");
    
    // Export the pubkey
    size_t pubkey_nbytes_copy = pubkey_nbytes - 1;
    is(cckem_export_pubkey(pubctx, &pubkey_nbytes_copy, exported_pubkey), CCERR_PARAMETER, "cckem_export_pubkey with invalid size");
    pubkey_nbytes_copy = pubkey_nbytes;
    is(cckem_export_pubkey(pubctx, &pubkey_nbytes_copy, exported_pubkey), CCERR_OK, "cckem_export_pubkey failure");
    
    // Import the pubkey
    is(cckem_import_pubkey(info, pubkey_nbytes_copy, exported_pubkey, exported_pub_ctx), CCERR_OK, "cckem_import_pubkey failure");
    
    // Encapsulate & decapsulate
    is(cckem_encapsulate(exported_pub_ctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_encapsulate, global_test_rng),
       CCERR_OK,
       "cckem_encapsulate: Encapsulation error after pubkey import");
    is(cckem_decapsulate(ctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_decapsulate), CCERR_OK, "cckem_decapsulate: Decapsulation error");
    ok_memcmp(sharedsecret_encapsulate, sharedsecret_decapsulate, sharedsecret_nbytes, "Shared secret invalid after export/import of pubkey");
    
    // Export the privkey
    size_t privkey_nbytes_copy = privkey_nbytes - 1;
    is(cckem_export_privkey(ctx, &privkey_nbytes_copy, exported_privkey), CCERR_PARAMETER, "cckem_export_privkey with invalid size");
    privkey_nbytes_copy = privkey_nbytes;
    is(cckem_export_privkey(ctx, &privkey_nbytes_copy, exported_privkey), CCERR_OK, "cckem_export_privkey failure");
    
    // Import the privkey
    is(cckem_import_privkey(info, privkey_nbytes_copy, exported_privkey, exported_priv_ctx), CCERR_OK, "cckem_import_privkey failure");
    
    // Decapsulate
    cc_memset(sharedsecret_decapsulate, 0x41, sharedsecret_nbytes);
    is(cckem_decapsulate(exported_priv_ctx, cckem_encapsulated_key_nbytes_info(info), ciphertext, cckem_shared_key_nbytes_info(info), sharedsecret_decapsulate), CCERR_OK, "cckem_decapsulate: Decapsulation error after privkey import");
    ok_memcmp(sharedsecret_encapsulate, sharedsecret_decapsulate, sharedsecret_nbytes, "Shared secret invalid after export/import of privkey");
}

static void cckem_derive_from_seed(const struct cckem_info *info)
{
    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);

    uint8_t seed[32];
    int rv = ccrng_generate(global_test_rng, sizeof(seed), seed);
    is(rv, CCERR_OK, "Generating seed failed");

    // Derive key from a random seed.
    rv = cckem_derive_key_from_seed(ctx, sizeof(seed), seed, global_test_rng);
    is(rv, CCERR_OK, "Deriving key from seed failed");

    uint8_t ek[cckem_encapsulated_key_nbytes_info(info)];
    uint8_t sk[cckem_shared_key_nbytes_info(info)];

    // Encapsulate.
    rv = cckem_encapsulate(cckem_public_ctx(ctx), sizeof(ek), ek, sizeof(sk), sk, global_test_rng);
    is(rv, CCERR_OK, "Encapsulation failed");

    cckem_full_ctx_decl(info, ctx2);
    cckem_full_ctx_init(ctx2, info);

    // Derive key from the random seed again.
    rv = cckem_derive_key_from_seed(ctx2, sizeof(seed), seed, global_test_rng);
    is(rv, CCERR_OK, "Deriving key from seed failed");

    // Check that derived keys (except Z) match.
    ok_memcmp(ctx->key, ctx2->key, info->fullkey_nbytes - 32, "Derived keys should match");

    // Decapsulate.
    uint8_t sk2[cckem_shared_key_nbytes_info(info)];
    rv = cckem_decapsulate(ctx2, sizeof(ek), ek, sizeof(sk2), sk2);
    is(rv, CCERR_OK, "Decapsulation failed");

    ok_memcmp(sk, sk2, sizeof(sk), "Shared keys don't match");

    cckem_full_ctx_decl(info, ctx3);
    cckem_full_ctx_init(ctx3, info);

    // Corrupt the seed and derive keys once more.
    seed[0] ^= 0x5a;
    rv = cckem_derive_key_from_seed(ctx3, sizeof(seed), seed, global_test_rng);
    is(rv, CCERR_OK, "Deriving key from seed failed");

    // Check that derived keys (except Z) do not match.
    isnt(memcmp(ctx->key, ctx3->key, info->fullkey_nbytes - 32), 0, "Derived keys should differ");

    // Decapsulate with the wrong key.
    uint8_t sk3[cckem_shared_key_nbytes_info(info)];
    rv = cckem_decapsulate(ctx3, sizeof(ek), ek, sizeof(sk3), sk3);
    is(rv, CCERR_OK, "Decapsulation failed");

    isnt(memcmp(sk, sk3, sizeof(sk)), 0, "Shared keys shouldn't match");
}

struct cckem_test_entry {
    void (*test_func)(const struct cckem_info *);
    size_t test_count;
    const struct cckem_info *info;
};

int cckem_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    struct cckem_test_entry tests[] = {
        { &cckem_encapsulate_decapsulate, 4, cckem_kyber768() },
        { &cckem_encapsulate_decapsulate, 4, cckem_kyber1024() },
        { &cckem_export_import, 13, cckem_kyber768() },
        { &cckem_export_import, 13, cckem_kyber1024() },
        { &cckem_derive_from_seed, 11, cckem_kyber768() },
        { &cckem_derive_from_seed, 11, cckem_kyber1024() },
    };

    int ntests = 0;
    for (size_t i = 0; i < CC_ARRAY_LEN(tests); i++) {
        ntests += tests[i].test_count;
    }
    plan_tests(ntests);

    for (size_t i = 0; i < CC_ARRAY_LEN(tests); i++) {
        tests[i].test_func(tests[i].info);
    }

    return 0;
}
