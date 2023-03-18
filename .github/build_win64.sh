#!/bin/sh
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

rm -rf build_win64
mkdir -p build_win64 && cd build_win64

#cmake .. --toolchain ../cmake_modules/toolchain_mingw.cmake -D USE_CRYPTO="BCrypt" -Dprotobuf_BUILD_TESTS=OFF
cmake .. --toolchain ../cmake_modules/toolchain_mingw.cmake -DGITHUB_RUNNER_COMPILE=ON && make -j10 openjkdf2-64
cd ..

./scripts/helper_CopyMinGWDLLs.sh