#!/bin/bash
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

#NDK_TOOLCHAIN_BINS=$(dirname $(find "$ANDROID_NDK_HOME/" -name "aarch64-linux-android31-clang"))
#PATH=$PATH:$NDK_TOOLCHAIN_BINS

#rm -rf build_win64
mkdir -p build_nintendo_dsi && pushd build_nintendo_dsi
OPENJKDF2_BUILD_DIR=$(pwd)

# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

EXPERIMENTAL_FIXED_POINT=1
DEBUG_QOL_CHEATS=1
EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_twl.cmake &&
(EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j $(nproc) openjkdf2.nds || EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j1 openjkdf2.nds)
if [ $? -ne 0 ]; then
    exit -1
fi
popd

echo "Starting..." && \
pkill -9 melonDS ; pkill -9 melonDS ; /Applications/melonDS.app/Contents/MacOS/melonDS build_nintendo_dsi/openjkdf2.nds
