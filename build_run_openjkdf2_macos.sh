#!/bin/zsh

export PATH="${HOMEBREW_PREFIX}/opt/llvm/bin:$PATH"

cd /Users/maxamillion/workspace/OpenJKDF2/

make flex/flex
make byacc/yacc

#cp DF2/player_bak/Max/Max.plr ~/.local/share/openjkdf2/player/Max/Max.plr
#OPENJKDF2_NO_ASAN=1 DEBUG_QOL_CHEATS=1 make -f Makefile.macos -j10 &&
mkdir -p build_darwin64 && cd build_darwin64
DEBUG_QOL_CHEATS=1 cmake .. &&
DEBUG_QOL_CHEATS=1 make -j10 &&
cd .. &&
#cp resource/shaders/* DF2/resource/shaders/ &&
mkdir -p ~/.local/share/openjkdf2/resource/shaders/ &&
cp resource/shaders/* ~/.local/share/openjkdf2/resource/shaders/ &&
echo "Running..." &&
#codesign -s - openjkdf2-64 &&
#LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="detect_leaks=1:log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log"  lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64
lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64
#open OpenJKDF2.app


#LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="detect_leaks=1:log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log" ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 