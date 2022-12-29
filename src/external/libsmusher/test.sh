#!/bin/zsh

CWD=$(pwd)
mkdir -p build && cd build && cmake .. && make && $CWD/build/libsmusher_standalone $CWD/JKMINTRO.SAN