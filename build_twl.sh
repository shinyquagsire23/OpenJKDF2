#!/bin/sh
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

#NDK_TOOLCHAIN_BINS=$(dirname $(find "$ANDROID_NDK_HOME/" -name "aarch64-linux-android31-clang"))
#PATH=$PATH:$NDK_TOOLCHAIN_BINS

#rm -rf build_win64
mkdir -p build_nintendo_dsi && cd build_nintendo_dsi
OPENJKDF2_BUILD_DIR=$(pwd)

# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_twl.cmake && make -j10 openjkdf2.nds
cd ..
