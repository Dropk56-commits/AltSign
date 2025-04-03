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
 * Some contents of this file are extracted from xnu source. Licenses follow:
 */

/*
 * Copyright (c) 2007-2024 Apple Inc. All rights reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 */

/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#ifndef _CC_CPU_H_
#define _CC_CPU_H_

#if defined(__arm64__) && CC_DARWIN
#include <arm/cpu_capabilities.h>

#if CC_KERNEL
extern uint64_t cpu_feature_bits;

void cc_init_feature_bits(void);

CC_INLINE bool cc_cpu_supports(uint64_t flag) {
    return cpu_feature_bits & flag;
}
#else /* !CC_KERNEL */
#if __has_feature(address_sanitizer)
 #define CC_COMMPAGE_CPU_CAPABILITIES \
        (*((volatile __attribute__((address_space(1))) uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64))
#else
 #define CC_COMMPAGE_CPU_CAPABILITIES \
        (*((volatile uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64))
#endif /* __has_feature(address_sanitizer) */

CC_INLINE bool cc_cpu_supports(uint64_t flag)
{
    return CC_COMMPAGE_CPU_CAPABILITIES & flag;
}
#endif /* !CC_KERNEL */

/*  osfmk/arm64/proc_reg.h */
#define ID_AA64ISAR0_EL1_TS_OFFSET    52
#define ID_AA64ISAR0_EL1_TS_MASK      (0xfull << ID_AA64ISAR0_EL1_TS_OFFSET)
#define ID_AA64ISAR0_EL1_TS_FLAGM_EN  (1ull << ID_AA64ISAR0_EL1_TS_OFFSET)
#define ID_AA64ISAR0_EL1_TS_FLAGM2_EN (2ull << ID_AA64ISAR0_EL1_TS_OFFSET)

#define ID_AA64ISAR0_EL1_FHM_OFFSET    48
#define ID_AA64ISAR0_EL1_FHM_MASK      (0xfull << ID_AA64ISAR0_EL1_FHM_OFFSET)
#define ID_AA64ISAR0_EL1_FHM_8_2       (1ull << ID_AA64ISAR0_EL1_FHM_OFFSET)

#define ID_AA64ISAR0_EL1_DP_OFFSET     44
#define ID_AA64ISAR0_EL1_DP_MASK       (0xfull << ID_AA64ISAR0_EL1_DP_OFFSET)
#define ID_AA64ISAR0_EL1_DP_EN         (1ull << ID_AA64ISAR0_EL1_DP_OFFSET)

#define ID_AA64ISAR0_EL1_SHA3_OFFSET   32
#define ID_AA64ISAR0_EL1_SHA3_MASK     (0xfull << ID_AA64ISAR0_EL1_SHA3_OFFSET)
#define ID_AA64ISAR0_EL1_SHA3_EN       (1ull << ID_AA64ISAR0_EL1_SHA3_OFFSET)

#define ID_AA64ISAR0_EL1_RDM_OFFSET    28
#define ID_AA64ISAR0_EL1_RDM_MASK      (0xfull << ID_AA64ISAR0_EL1_RDM_OFFSET)
#define ID_AA64ISAR0_EL1_RDM_EN        (1ull << ID_AA64ISAR0_EL1_RDM_OFFSET)

#define ID_AA64ISAR0_EL1_ATOMIC_OFFSET 20
#define ID_AA64ISAR0_EL1_ATOMIC_MASK   (0xfull << ID_AA64ISAR0_EL1_ATOMIC_OFFSET)
#define ID_AA64ISAR0_EL1_ATOMIC_8_1    (2ull << ID_AA64ISAR0_EL1_ATOMIC_OFFSET)

#define ID_AA64ISAR0_EL1_CRC32_OFFSET  16
#define ID_AA64ISAR0_EL1_CRC32_MASK    (0xfull << ID_AA64ISAR0_EL1_CRC32_OFFSET)
#define ID_AA64ISAR0_EL1_CRC32_EN      (1ull << ID_AA64ISAR0_EL1_CRC32_OFFSET)

#define ID_AA64ISAR0_EL1_SHA2_OFFSET   12
#define ID_AA64ISAR0_EL1_SHA2_MASK     (0xfull << ID_AA64ISAR0_EL1_SHA2_OFFSET)
#define ID_AA64ISAR0_EL1_SHA2_EN       (1ull << ID_AA64ISAR0_EL1_SHA2_OFFSET)
#define ID_AA64ISAR0_EL1_SHA2_512_EN   (2ull << ID_AA64ISAR0_EL1_SHA2_OFFSET)

#define ID_AA64ISAR0_EL1_SHA1_OFFSET   8
#define ID_AA64ISAR0_EL1_SHA1_MASK     (0xfull << ID_AA64ISAR0_EL1_SHA1_OFFSET)
#define ID_AA64ISAR0_EL1_SHA1_EN       (1ull << ID_AA64ISAR0_EL1_SHA1_OFFSET)

#define ID_AA64ISAR0_EL1_AES_OFFSET    4
#define ID_AA64ISAR0_EL1_AES_MASK      (0xfull << ID_AA64ISAR0_EL1_AES_OFFSET)
#define ID_AA64ISAR0_EL1_AES_EN        (1ull << ID_AA64ISAR0_EL1_AES_OFFSET)
#define ID_AA64ISAR0_EL1_AES_PMULL_EN  (2ull << ID_AA64ISAR0_EL1_AES_OFFSET)

#define ID_AA64ISAR1_EL1_I8MM_OFFSET    52
#define ID_AA64ISAR1_EL1_I8MM_MASK      (0xfull << ID_AA64ISAR1_EL1_I8MM_OFFSET)
#define ID_AA64ISAR1_EL1_I8MM_EN        (1ull << ID_AA64ISAR1_EL1_I8MM_OFFSET)

#define ID_AA64ISAR1_EL1_DGH_OFFSET     48
#define ID_AA64ISAR1_EL1_DGH_MASK       (0xfull << ID_AA64ISAR1_EL1_DGH_OFFSET)

#define ID_AA64ISAR1_EL1_BF16_OFFSET    44
#define ID_AA64ISAR1_EL1_BF16_MASK      (0xfull << ID_AA64ISAR1_EL1_BF16_OFFSET)
#define ID_AA64ISAR1_EL1_BF16_EN        (1ull << ID_AA64ISAR1_EL1_BF16_OFFSET)

#define ID_AA64ISAR1_EL1_SPECRES_OFFSET 40
#define ID_AA64ISAR1_EL1_SPECRES_MASK   (0xfull << ID_AA64ISAR1_EL1_SPECRES_OFFSET)
#define ID_AA64ISAR1_EL1_SPECRES_EN     (1ull << ID_AA64ISAR1_EL1_SPECRES_OFFSET)

#define ID_AA64ISAR1_EL1_SB_OFFSET      36
#define ID_AA64ISAR1_EL1_SB_MASK        (0xfull << ID_AA64ISAR1_EL1_SB_OFFSET)
#define ID_AA64ISAR1_EL1_SB_EN          (1ull << ID_AA64ISAR1_EL1_SB_OFFSET)

#define ID_AA64ISAR1_EL1_FRINTTS_OFFSET 32
#define ID_AA64ISAR1_EL1_FRINTTS_MASK   (0xfull << ID_AA64ISAR1_EL1_FRINTTS_OFFSET)
#define ID_AA64ISAR1_EL1_FRINTTS_EN     (1ull << ID_AA64ISAR1_EL1_FRINTTS_OFFSET)

#define ID_AA64ISAR1_EL1_GPI_OFFSET     28
#define ID_AA64ISAR1_EL1_GPI_MASK       (0xfull << ID_AA64ISAR1_EL1_GPI_OFFSET)
#define ID_AA64ISAR1_EL1_GPI_EN         (1ull << ID_AA64ISAR1_EL1_GPI_OFFSET)

#define ID_AA64ISAR1_EL1_GPA_OFFSET     24
#define ID_AA64ISAR1_EL1_GPA_MASK       (0xfull << ID_AA64ISAR1_EL1_GPA_OFFSET)

#define ID_AA64ISAR1_EL1_LRCPC_OFFSET   20
#define ID_AA64ISAR1_EL1_LRCPC_MASK     (0xfull << ID_AA64ISAR1_EL1_LRCPC_OFFSET)
#define ID_AA64ISAR1_EL1_LRCPC_EN       (1ull << ID_AA64ISAR1_EL1_LRCPC_OFFSET)
#define ID_AA64ISAR1_EL1_LRCP2C_EN      (2ull << ID_AA64ISAR1_EL1_LRCPC_OFFSET)

#define ID_AA64ISAR1_EL1_FCMA_OFFSET    16
#define ID_AA64ISAR1_EL1_FCMA_MASK      (0xfull << ID_AA64ISAR1_EL1_FCMA_OFFSET)
#define ID_AA64ISAR1_EL1_FCMA_EN        (1ull << ID_AA64ISAR1_EL1_FCMA_OFFSET)

#define ID_AA64ISAR1_EL1_JSCVT_OFFSET   12
#define ID_AA64ISAR1_EL1_JSCVT_MASK     (0xfull << ID_AA64ISAR1_EL1_JSCVT_OFFSET)
#define ID_AA64ISAR1_EL1_JSCVT_EN       (1ull << ID_AA64ISAR1_EL1_JSCVT_OFFSET)

#define ID_AA64ISAR1_EL1_API_OFFSET     8
#define ID_AA64ISAR1_EL1_API_MASK       (0xfull << ID_AA64ISAR1_EL1_API_OFFSET)
#define ID_AA64ISAR1_EL1_API_PAuth_EN   (1ull << ID_AA64ISAR1_EL1_API_OFFSET)
#define ID_AA64ISAR1_EL1_API_PAuth2_EN  (3ull << ID_AA64ISAR1_EL1_API_OFFSET)
#define ID_AA64ISAR1_EL1_API_FPAC_EN    (4ull << ID_AA64ISAR1_EL1_API_OFFSET)
#define ID_AA64ISAR1_EL1_API_FPACCOMBINE (5ull << ID_AA64ISAR1_EL1_API_OFFSET)

#define ID_AA64ISAR1_EL1_APA_OFFSET     4
#define ID_AA64ISAR1_EL1_APA_MASK       (0xfull << ID_AA64ISAR1_EL1_APA_OFFSET)

#define ID_AA64ISAR1_EL1_DPB_OFFSET     0
#define ID_AA64ISAR1_EL1_DPB_MASK       (0xfull << ID_AA64ISAR1_EL1_DPB_OFFSET)
#define ID_AA64ISAR1_EL1_DPB_EN         (1ull << ID_AA64ISAR1_EL1_DPB_OFFSET)
#define ID_AA64ISAR1_EL1_DPB2_EN        (2ull << ID_AA64ISAR1_EL1_DPB_OFFSET)

#define ID_AA64PFR0_EL1_CSV3_OFFSET     60
#define ID_AA64PFR0_EL1_CSV3_MASK       (0xfull << ID_AA64PFR0_EL1_CSV3_OFFSET)
#define ID_AA64PFR0_EL1_CSV3_EN         (1ull << ID_AA64PFR0_EL1_CSV3_OFFSET)

#define ID_AA64PFR0_EL1_CSV2_OFFSET     56
#define ID_AA64PFR0_EL1_CSV2_MASK       (0xfull << ID_AA64PFR0_EL1_CSV2_OFFSET)
#define ID_AA64PFR0_EL1_CSV2_EN         (1ull << ID_AA64PFR0_EL1_CSV2_OFFSET)

#define ID_AA64PFR0_EL1_DIT_OFFSET     48
#define ID_AA64PFR0_EL1_DIT_MASK       (0xfull << ID_AA64PFR0_EL1_DIT_OFFSET)
#define ID_AA64PFR0_EL1_DIT_EN         (1ull << ID_AA64PFR0_EL1_DIT_OFFSET)

#define ID_AA64PFR0_EL1_AdvSIMD_OFFSET  20
#define ID_AA64PFR0_EL1_AdvSIMD_MASK    (0xfull << ID_AA64PFR0_EL1_AdvSIMD_OFFSET)
#define ID_AA64PFR0_EL1_AdvSIMD_HPFPCVT (0x0ull << ID_AA64PFR0_EL1_AdvSIMD_OFFSET)
#define ID_AA64PFR0_EL1_AdvSIMD_FP16    (0x1ull << ID_AA64PFR0_EL1_AdvSIMD_OFFSET)
#define ID_AA64PFR0_EL1_AdvSIMD_DIS     (0xfull << ID_AA64PFR0_EL1_AdvSIMD_OFFSET)

#endif /* defined(__arm64__) && CC_DARWIN */

#endif /* _CC_CPU_H_ */
