#!/bin/zsh
cd /Users/maxamillion/workspace/OpenJKDF2/
#OPENJKDF2_NO_ASAN=1 DEBUG_QOL_CHEATS=1 make -f Makefile.macos -j10 &&
DEBUG_QOL_CHEATS=1 make -f Makefile.macos -j10 &&
cp openjkdf2-64 DF2/openjkdf2-64 &&
cp -r openjkdf2-64.dsym DF2/openjkdf2-64.dsym &&
cp resource/shaders/* DF2/resource/shaders/ &&
cd DF2 &&
echo "Running..." &&
codesign -s - openjkdf2-64 &&
lldb -o run ./openjkdf2-64
#./openjkdf2-64