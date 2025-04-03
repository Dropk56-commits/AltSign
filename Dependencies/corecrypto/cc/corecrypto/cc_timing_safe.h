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

/*
 Temporary port of libplatform "timingsafe.h"
 */

#ifndef _CORECRYPTO_CC_TIMING_SAFE_H_
#define _CORECRYPTO_CC_TIMING_SAFE_H_

#include "cc_internal.h"

#if CC_DIT_WITH_SB_MAYBE_SUPPORTED

#include <stdbool.h>
#include <stdint.h>

/**
 Definition of supported CPU features.
 */
typedef enum {
    TIMINGSAFE_FEATURE_NONE = 0,
    TIMINGSAFE_FEATURE_DIT = 1,
} timingsafe_features_t;

/**
 Token used to track state from enable() to disable().
 */
typedef timingsafe_features_t timingsafe_token_t;

/**
 @function timingsafe_get_features

 @return feature set supported by the calling CPU.
 */
timingsafe_features_t timingsafe_get_features(void);

/**
 @function timingsafe_is_enabled

 @return true if and only if timingsafe features are enabled on the calling CPU.
 */
bool timingsafe_is_enabled(void);

/**
 @function timingsafe_enable_if_supported
 @abstract Unconditionally enable all supported timingsafe features.
 If timingsafe features aren't supported, they are ignored. If no features are
 supported, this is a no-op.

 @return The opaque token to use in timingsafe_restore_if_supported().
 */
timingsafe_token_t timingsafe_enable_if_supported(void);

/**
 @function timingsafe_restore_if_supported
 @abstract Restore timingsafe features to the state they were in before calling
 timingsafe_enable_if_supported and given the provided token.

 @param token The token returned by timingsafe_enable_if_supported.
 */
void timingsafe_restore_if_supported(timingsafe_token_t token);

#endif /* CC_DIT_WITH_SB_MAYBE_SUPPORTED */

#endif /* _CORECRYPTO_CC_TIMING_SAFE_H_ */
