#!/bin/zsh
#make flex/flex
#make byacc/yacc

rm -rf build_win64
mkdir -p build_win64 && cd build_win64

#cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake -D USE_CRYPTO="BCrypt" -Dprotobuf_BUILD_TESTS=OFF
cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake -DGITHUB_RUNNER_COMPILE=ON && make -j10 openjkdf2-64
cd ..

./scripts/helper_CopyMinGWDLLs.sh