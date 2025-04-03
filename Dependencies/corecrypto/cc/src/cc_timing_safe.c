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

#include "cc_internal.h"

#if CC_DIT_WITH_SB_MAYBE_SUPPORTED

#include "cc_runtime_config.h"

#include "cc_timing_safe.h"
#include <stdbool.h>
#include <stdint.h>

#define REG_DIT "dit"
#define REG_SB "sb"
#define DIT_ON (1)
#define DIT_OFF (0)
#define BARRIER_SY (0xf)


/**
 CPU capabilities from commpage.
 */
typedef uint64_t cpu_cap_t;

__attribute__((target(REG_DIT))) static inline bool is_dit_enabled(void) {
    return 0 != __builtin_arm_rsr64(REG_DIT);
}

__attribute__((target(REG_SB))) static inline void sb(void) {
    __asm__ __volatile__(REG_SB::: "memory");
}

static inline void speculation_barrier(void) {
    if (CC_HAS_SB() && CC_INTERNAL_SDK) {
        sb();
    } else {
        __builtin_arm_dsb(BARRIER_SY);
        __builtin_arm_isb(BARRIER_SY);
    }
}

__attribute__((target(REG_DIT))) timingsafe_token_t
timingsafe_enable_if_supported(void) {
    timingsafe_token_t token = TIMINGSAFE_FEATURE_NONE;
    if (CC_HAS_DIT() && CC_INTERNAL_SDK) {
        if (is_dit_enabled()) {
            token |= TIMINGSAFE_FEATURE_DIT;
        }
        __builtin_arm_wsr64(REG_DIT, DIT_ON);
    }
    speculation_barrier();
    return token;
}

__attribute__((target(REG_DIT))) void
timingsafe_restore_if_supported(timingsafe_token_t token) {
    if (CC_HAS_DIT() && CC_INTERNAL_SDK && !(token & TIMINGSAFE_FEATURE_DIT)) {
        // Disable DIT if it was previously disabled
        __builtin_arm_wsr64(REG_DIT, DIT_OFF);
    }
}

bool timingsafe_is_enabled(void) {
    bool is_enabled = false;
    if (!(CC_HAS_DIT() && CC_INTERNAL_SDK)) {
        goto out;
    }
    is_enabled = is_dit_enabled();

out:
    return is_enabled;
}

timingsafe_features_t timingsafe_get_features(void) {
    timingsafe_features_t out_features = 0;

    if (CC_HAS_DIT() && CC_INTERNAL_SDK) {
        out_features |= TIMINGSAFE_FEATURE_DIT;
    }

    return out_features;
}

#endif /* CC_DIT_WITH_SB_MAYBE_SUPPORTED */
