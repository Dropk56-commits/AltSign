/* Copyright (c) (2017,2019-2022,2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdio.h>
#include <libSEPOS.h>
#include <if_SEPOS.h>

#include "fipspost.h"
#include "fipspost_l4.h"

void fipspost_l4_post(uint32_t fips_mod)
{
    printf("SEP: FIPS POST begin\n");
    int ret = fipspost_post(fips_mod, (struct mach_header*)&_mh_execute_header);
    if (ret != 0) {
        /*
         * POST has failed; drop into a while(1) loop for a few seconds to allow
         * logs to exfiltrate and then panic.
         */
        printf("SEP: FIPS POST failed; stalling before panic\n");
        thread_usleep(3000000);
        sys_panic("Failed FIPS POST");
    }
    printf("sks: FIPS POST Succeeded\n");
}
