#!/bin/bash
# 32-bit Windows XP build using the legacy OpenGL 1.1 fixed-function renderer.

CX_ROOT="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver"
CX_BOTTLE="General"
WINEPREFIX="/Users/maxamillion/Library/Application Support/CrossOver/Bottles/General"
WINEDLLPATH="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/lib32on64/wine"

WINELOADER="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wineloader32on64"
WINESERVER="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wineserver"

WINEDEBUG=all

./build_winxp32.sh &&
cp build_win32/openjkdf2-32.exe DF2/openjkdf2-32.exe &&
cp build_win32/*.dll DF2/ &&

pushd DF2 &&
PATH="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin:/usr/bin:/bin:/usr/sbin:/sbin" DYLD_LIBRARY_PATH="/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/lib64:/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/lib32on64" /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine --bottle "General" /Users/maxamillion/workspace/OpenJKDF2/DF2/openjkdf2-32.exe -windowgui ;
popd