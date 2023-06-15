#!/bin/sh

export PATH="${HOMEBREW_PREFIX}/opt/llvm/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET=10.15
export CC=/opt/homebrew/opt/llvm/bin/clang
export CXX=/opt/homebrew/opt/llvm/bin/clang++

cd /Users/maxamillion/workspace/OpenJKDF2/

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

mkdir -p build_darwin64 && cd build_darwin64

export PKG_CONFIG_PATH_OLD=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD:/opt/homebrew/opt/openssl@1.1/lib/pkgconfig
DEBUG_QOL_CHEATS=0 OPENJKDF2_NO_ASAN=0 cmake .. &&
DEBUG_QOL_CHEATS=0 OPENJKDF2_NO_ASAN=0 make -j10 &&
cd .. &&
#cp resource/shaders/* DF2/resource/shaders/ &&
mkdir -p "/Users/maxamillion/Library/Application Support/OpenJKDF2/openjkmots/resource/shaders/" &&
cp resource/shaders/* "/Users/maxamillion/Library/Application Support/OpenJKDF2/openjkmots/resource/shaders/" &&
echo "Running..." &&
#codesign -s - openjkdf2-64 &&
#OPENJKMOTS_ROOT="~/Library/Application Support/OpenJKDF2/openjkmots" LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log"  lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 -- -motsCompat #-- -verboseNetworking
#OPENJKDF2_ROOT="~/Library/Application Support/OpenJKDF2/openjkmots" LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log"  lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 #-- -verboseNetworking
#lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 -- -motsCompat -path research #-- -verboseNetworking
LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log detect_leaks=0"  lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 -- -motsCompat #-- -verboseNetworking
#lldb -o run ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64
#open OpenJKDF2.app


#LSAN_OPTIONS="suppressions=/Users/maxamillion/workspace/OpenJKDF2/suppr.txt" ASAN_OPTIONS="detect_leaks=1:log_path=/Users/maxamillion/workspace/OpenJKDF2/asan.log" ./OpenJKDF2.app/Contents/MacOS/openjkdf2-64 