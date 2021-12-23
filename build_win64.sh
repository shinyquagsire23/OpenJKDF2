#!/bin/zsh
make flex/flex
make byacc/yacc

rm -rf build_win64
mkdir -p build_win64
cd build_win64
pwd
cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake && make -j10
cd ..