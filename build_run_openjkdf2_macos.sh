#!/bin/zsh
cd /Users/maxamillion/workspace/OpenJKDF2/
#cp DF2/player_bak/Max/Max.plr ~/.local/share/openjkdf2/player/Max/Max.plr
#OPENJKDF2_NO_ASAN=1 DEBUG_QOL_CHEATS=1 make -f Makefile.macos -j10 &&
DEBUG_QOL_CHEATS=1 make -f Makefile.macos -j10 &&
cp resource/shaders/* DF2/resource/shaders/ &&
cp resource/shaders/* ~/.local/share/openjkdf2/resource/shaders/ &&
echo "Running..." &&
#codesign -s - openjkdf2-64 &&
lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64
#open OpenJKDF2.app