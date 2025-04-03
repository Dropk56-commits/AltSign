# Copyright (c) (2021,2024) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/sh

set -x

# Why not just install these libraries under the link names to begin
# with? The issue is the build system puts all build variants in a
# single flat directory.
#
# As a workaround, we create symlinks after the fact.

library_basename=$(basename -s "${EXECUTABLE_SUFFIX}" "${EXECUTABLE_NAME}")

for variant in ${BUILD_VARIANTS}; do
    case "${variant}" in
        normal)
            continue
            ;;
    esac

    library_name="${EXECUTABLE_PREFIX}${PRODUCT_NAME}_${variant}${EXECUTABLE_SUFFIX}"
    symlink_subdir=$(echo ${variant} | tr '[a-z]' '[A-Z]')
    symlink_dir="${TARGET_BUILD_DIR}/${symlink_subdir}"
    mkdir -p "${symlink_dir}"
    symlink_path=$(python3 -c \
                           'import os.path, sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' \
                           "${TARGET_BUILD_DIR}/${library_name}" \
                           "${symlink_dir}")
    ln -s -f "${symlink_path}" "${symlink_dir}/${EXECUTABLE_NAME}"
done

