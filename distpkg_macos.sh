#!/bin/sh

export PATH="${HOMEBREW_PREFIX}/opt/llvm/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET=10.15
export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

rm -rf OpenJKDF2.app
rm -rf OpenJKDF2_x86_64.app
rm -rf OpenJKDF2_arm64.app
rm -rf OpenJKDF2_universal.app

rm -rf build_darwin_x86_64
rm -rf build_darwin64

rm -f macos-debug.tar.gz

rm -f src/globals.h
rm -f src/globals.c

#
# x86_64
#

mkdir -p build_darwin_x86_64 && pushd build_darwin_x86_64

export PKG_CONFIG_PATH_OLD=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD:/usr/local/opt/openssl@1.1/lib/pkgconfig

cmake .. -DPLAT_MACOS_X86_64=true --toolchain $(pwd)/../cmake_modules/toolchain_macos_x86_64.cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" &&
cmake .. -DPLAT_MACOS_X86_64=true --toolchain $(pwd)/../cmake_modules/toolchain_macos_x86_64.cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
( make -j1 openjkdf2-64 || make -j1 openjkdf2-64)
if [ $? -ne 0 ]; then
    exit -1
fi
popd

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD

#
# ARM64
#

mkdir -p build_darwin64 && pushd build_darwin64

export PKG_CONFIG_PATH_OLD=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD:/opt/homebrew/opt/openssl@1.1/lib/pkgconfig

cmake .. &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
(make -j $(nproc) openjkdf2-64 || make -j1 openjkdf2-64)
if [ $? -ne 0 ]; then
    exit -1
fi
popd

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD

./combine_macos_appbundles.sh

#zip -r macos-debug.zip OpenJKDF2_universal.app resource
#tar czf macos-debug.tar.gz OpenJKDF2_universal.app resource
tar czf macos-debug.tar.gz OpenJKDF2_universal.app

rm -rf build_darwin_x86_64
rm -rf build_darwin64

rm -rf OpenJKDF2.app
rm -rf OpenJKDF2_x86_64.app
rm -rf OpenJKDF2_arm64.app
rm -rf OpenJKDF2_universal.app
