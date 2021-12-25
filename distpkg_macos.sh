#!/bin/zsh

rm -rf OpenJKDF2.app
rm -rf OpenJKDF2_x86_64.app
rm -rf OpenJKDF2_arm64.app
rm -rf OpenJKDF2_universal.app

rm -rf build_darwin_x86_64
rm -rf build_darwin64

mkdir -p build_darwin_x86_64 && cd build_darwin_x86_64
cmake .. -DPLAT_MACOS_X86_64=true &&
make -j10 &&
cd .. &&


mkdir -p build_darwin64 && cd build_darwin64
cmake .. &&
make -j10 &&
cd .. &&

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