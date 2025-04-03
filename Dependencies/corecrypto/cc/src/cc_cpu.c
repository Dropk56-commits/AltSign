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

#include "cc.h"
#include "cc_cpu.h"

#if defined(__arm64__) && CC_KERNEL
static bool cc_cpu_feat_initialized;
uint64_t cpu_feature_bits = 0;

void cc_init_feature_bits(void) {
    if (!cc_cpu_feat_initialized) {
        uint64_t isar0 = __builtin_arm_rsr64("ID_AA64ISAR0_EL1");
        uint64_t pfr0 = __builtin_arm_rsr64("ID_AA64PFR0_EL1");

        if ((pfr0 & ID_AA64PFR0_EL1_DIT_MASK) >= ID_AA64PFR0_EL1_DIT_EN) {
            cpu_feature_bits |= kHasFeatDIT;
        }

        if ((isar0 & ID_AA64ISAR0_EL1_SHA3_MASK) >= ID_AA64ISAR0_EL1_SHA3_EN) {
            cpu_feature_bits |= kHasFeatSHA3;
        }

        if ((isar0 & ID_AA64ISAR0_EL1_SHA2_MASK) >= ID_AA64ISAR0_EL1_SHA2_512_EN) {
            cpu_feature_bits |= kHasFeatSHA512;
        }

        cc_cpu_feat_initialized = true;
    }
}
#endif /* defined(__arm64__)  && CC_KERNEL */
