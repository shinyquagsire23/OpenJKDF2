#!/bin/bash
# 32-bit Windows XP build using the legacy OpenGL 1.1 fixed-function renderer.

export OPENJKDF2_RELEASE_COMMIT="$(git log -1 --format="%H")" \
       OPENJKDF2_RELEASE_COMMIT_SHORT="$(git rev-parse --short=8 HEAD)" &&
# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH &&

#rm -rf build_win32
mkdir -p build_win32 && pushd build_win32 &&

TARGET_BUILD_TESTS=1 cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_mingw_x86_32.cmake &&
make -j $(nproc) openjkdf2-32 &&
popd &&
./scripts/helper_CopyMinGWDLLs_x86_32.sh
