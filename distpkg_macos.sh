#!/bin/zsh

rm -rf OpenJKDF2.app
rm -rf OpenJKDF2_x86_64.app
rm -rf OpenJKDF2_arm64.app
rm -rf OpenJKDF2_universal.app

OPENJKDF2_NO_ASAN=1 OPENJKDF2_x86_64=1 make -f Makefile.macos clean
OPENJKDF2_NO_ASAN=1 OPENJKDF2_x86_64=1 make -f Makefile.macos -j10

OPENJKDF2_NO_ASAN=1 make -f Makefile.macos clean
OPENJKDF2_NO_ASAN=1 make -f Makefile.macos -j10

./combine_macos_appbundles.sh

#zip -r macos-debug.zip OpenJKDF2_universal.app resource
tar czf macos-debug.tar.gz OpenJKDF2_universal.app resource

OPENJKDF2_x86_64=1 make -f Makefile.macos clean
make -f Makefile.macos clean

rm -rf OpenJKDF2.app
rm -rf OpenJKDF2_x86_64.app
rm -rf OpenJKDF2_arm64.app
rm -rf OpenJKDF2_universal.app