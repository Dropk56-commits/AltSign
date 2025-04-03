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

#include <RTKit.h>
#include <stdio.h>

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

#include "cc_internal.h"
#include "cctv_internal.h"
#include "ccpost_internal.h"

RTK_CRT_INIT_STACK(4096);         // declare 4k init stack before threading is enabled
RTK_CRT_INTERRUPT_STACK(4096);    // 4k interrupt mode stack
RTK_CRT_FIQ_STACK(4096);          // 4k fiq mode stack
RTK_CRT_EXCEPTION_STACK(4096);    // 4k exception stack (UDFs, SVCs, etc..)

RTK_LIB_MALLOC_HEAP(512 * 1024);  // statically declare 512k of heap space

int
main(int argc, char **argv)
{
    RTK_platform_init();

    CCTV_DIGEST_SHA1_SHORT_MESSAGE_VECTOR_LIST_DECL(sha1_short_message_vectors);
    CCTV_DIGEST_SHA1_LONG_MESSAGE_VECTOR_LIST_DECL(sha1_long_message_vectors);
    CCTV_DIGEST_SHA224_SHORT_MESSAGE_VECTOR_LIST_DECL(sha224_short_message_vectors);
    CCTV_DIGEST_SHA224_LONG_MESSAGE_VECTOR_LIST_DECL(sha224_long_message_vectors);
    CCTV_DIGEST_SHA256_SHORT_MESSAGE_VECTOR_LIST_DECL(sha256_short_message_vectors);
    CCTV_DIGEST_SHA256_LONG_MESSAGE_VECTOR_LIST_DECL(sha256_long_message_vectors);
    CCTV_DIGEST_SHA384_SHORT_MESSAGE_VECTOR_LIST_DECL(sha384_short_message_vectors);
    CCTV_DIGEST_SHA384_LONG_MESSAGE_VECTOR_LIST_DECL(sha384_long_message_vectors);
    CCTV_DIGEST_SHA512_256_SHORT_MESSAGE_VECTOR_LIST_DECL(sha512_256_short_message_vectors);
    CCTV_DIGEST_SHA512_256_LONG_MESSAGE_VECTOR_LIST_DECL(sha512_256_long_message_vectors);
    CCTV_DIGEST_SHA512_SHORT_MESSAGE_VECTOR_LIST_DECL(sha512_short_message_vectors);
    CCTV_DIGEST_SHA512_LONG_MESSAGE_VECTOR_LIST_DECL(sha512_long_message_vectors);

    static const cctv_vector_t *vectors[] = {
        &sha1_short_message_vectors.vector,
        &sha1_long_message_vectors.vector,
        &sha224_short_message_vectors.vector,
        &sha224_long_message_vectors.vector,
        &sha256_short_message_vectors.vector,
        &sha256_long_message_vectors.vector,
        &sha384_short_message_vectors.vector,
        &sha384_long_message_vectors.vector,
        &sha512_256_short_message_vectors.vector,
        &sha512_256_long_message_vectors.vector,
        &sha512_short_message_vectors.vector,
        &sha512_long_message_vectors.vector,
    };
    cctv_vector_list_t vector_list = {
        .vector = {
            .type = CCTV_VECTOR_TYPE_VECTOR_LIST,
        },
        .list = vectors,
        .count = sizeof(vectors) / sizeof(vectors[0]),
    };

    ccpost_report_t report = { 0 };
    int status = ccpost(&vector_list.vector, &report);

    printf("test count: %llu\n", report.test_count);
    printf("fail count: %llu\n", report.fail_count);

    RTK_exit(status == CCERR_OK ? RTK_EXIT_SUCCESS : RTK_EXIT_FAILURE);

    // Unreachable
    return 0;
}
