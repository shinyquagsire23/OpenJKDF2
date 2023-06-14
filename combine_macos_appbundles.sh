#!/bin/sh

rm -rf OpenJKDF2_universal.app
cp -r OpenJKDF2.app OpenJKDF2_universal.app

rm -rf OpenJKDF2_universal.app/Contents/MacOS/openjkdf2-64.dsym
cp -r OpenJKDF2.app/Contents/MacOS/openjkdf2-64.dsym OpenJKDF2_universal.app/Contents/MacOS/openjkdf2-64_arm64.dsym
cp -r OpenJKDF2_x86_64.app/Contents/MacOS/openjkdf2-64.dsym OpenJKDF2_universal.app/Contents/MacOS/openjkdf2-64_x86_64.dsym

lipo -create -output OpenJKDF2_universal.app/Contents/MacOS/openjkdf2-64 OpenJKDF2.app/Contents/MacOS/openjkdf2-64 OpenJKDF2_x86_64.app/Contents/MacOS/openjkdf2-64

lipo -create -output OpenJKDF2_universal.app/Contents/MacOS/libz.1.dylib OpenJKDF2.app/Contents/MacOS/libz.1.dylib OpenJKDF2_x86_64.app/Contents/MacOS/libz.1.dylib

lipo -create -output OpenJKDF2_universal.app/Contents/MacOS/libGameNetworkingSockets.dylib OpenJKDF2.app/Contents/MacOS/libGameNetworkingSockets.dylib OpenJKDF2_x86_64.app/Contents/MacOS/libGameNetworkingSockets.dylib
lipo -create -output OpenJKDF2_universal.app/Contents/MacOS/libcrypto.1.1.dylib OpenJKDF2.app/Contents/MacOS/libcrypto.1.1.dylib OpenJKDF2_x86_64.app/Contents/MacOS/libcrypto.1.1.dylib

chmod 774 OpenJKDF2_universal.app/Contents/MacOS/openjkdf2-64
chmod 774 OpenJKDF2_universal.app/Contents/MacOS/*.dylib

codesign -s - OpenJKDF2_universal.app --force --deep --verbose

#tar czf macos-debug.tar.gz OpenJKDF2_universal.app