/* Copyright (c) (2021,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_internal.h"
#include "ccdigest_internal.h"

int ccsrp_generate_x(ccsrp_ctx_t srp,
                     cc_unit *x,
                     const char *username,
                     size_t salt_len,
                     const void *salt,
                     size_t password_len,
                     const void *password)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    uint8_t hash[MAX_DIGEST_OUTPUT_SIZE];

    ccdigest_di_decl(di, ctx);
    ccdigest_init_internal(di, ctx);
    if (!SRP_FLG(srp).noUsernameInX) {
        ccdigest_update_internal(di, ctx, strlen(username), username);
    }
    ccdigest_update_internal(di, ctx, 1, ":");
    ccdigest_update_internal(di, ctx, password_len, password);
    ccdigest_final(di, ctx, hash);
    ccdigest_init_internal(di, ctx);
    ccdigest_update_internal(di, ctx, salt_len, salt);
    ccdigest_update_internal(di, ctx, di->output_size, hash);
    ccdigest_final(di, ctx, hash);

    int status = ccsrp_import_ccn_with_len(srp, x, di->output_size, hash);

    cc_clear(di->output_size, hash);
    ccdigest_di_clear(di, ctx);
    return status;
}
