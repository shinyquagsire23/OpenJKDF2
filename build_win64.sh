#!/bin/zsh
make flex/flex
make byacc/yacc

mkdir -p build_mingw64_cmake && cd build_mingw64_cmake
cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake && make -j10
cd ..