# Copyright (c) (2024) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/usr/bin/env -S python3 -ESs

# Why not just install these libraries under the link names to begin
# with?
#
# There are a couple issues.
#
# First, all these links have the same file name but different install
# paths. This should be fine, but the build system puts intermediate
# build artifacts in flat directories and complains if there are name
# collisions.
#
# Second, we build all these libraries as build variants of a single
# target. Xcode's build system only evaluates ${INSTALL_PATH} once and
# not per-variant. This means you can't have different install paths
# for each one.
#
# As a workaround, we build the libraries under unique names and
# create links after the fact.

import os
from os import path
import glob
import re

dstroot = os.getenv('DSTROOT')
rtkit_root = os.getenv('RTKIT_ROOT', default='')
linkdir = path.normpath('{}/{}/usr/lib'.format(dstroot, rtkit_root))

executable_prefix = os.getenv('EXECUTABLE_PREFIX')
product_name = os.getenv('PRODUCT_NAME')
libprefix = '{}{}_'.format(executable_prefix, product_name)
libsuffix = os.getenv('EXECUTABLE_SUFFIX')

target_build_dir = os.getenv('TARGET_BUILD_DIR')
pattern = glob.escape(path.normpath('{}/{}'.format(target_build_dir, libprefix))) + '*'

for libpath in glob.iglob(pattern):
    libname = path.basename(libpath)
    match = re.fullmatch('{}(.*){}'.format(re.escape(libprefix),
                                           re.escape(libsuffix)),
                         libname)
    if not match:
        continue
    variant = match.group(1)
    rtk_variant = os.getenv('RTKIT_CURRENT_VARIANT_{}'.format(variant))
    rtk_config = os.getenv('RTKIT_CONFIGURATION_{}'.format(variant))
    slicename = os.getenv('RTKIT_SLICE_NAME_{}'.format(rtk_variant))
    slicedir = path.normpath('{}/{}/{}'.format(linkdir, rtk_config.capitalize(), slicename))
    librelpath = path.relpath(libpath, slicedir)
    os.makedirs(slicedir, exist_ok=True)
    os.symlink(librelpath, path.normpath('{}/{}'.format(slicedir, os.getenv('FULL_PRODUCT_NAME'))))

    if rtk_config == 'release':
        barelibname = '{}{}{}'.format(libprefix, rtk_variant, libsuffix)
        os.symlink(libname, path.normpath('{}/{}'.format(target_build_dir, barelibname)))
