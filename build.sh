#!/bin/zsh
make flex/flex
make byacc/yacc

mkdir -p build_hooks && cd build_hooks
cmake .. --toolchain ../cmake_modules/mingw_32_toolchain.cmake && make -j10
cd ..