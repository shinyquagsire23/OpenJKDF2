#!/bin/sh
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

NDK_TOOLCHAIN_BINS=$(dirname $(find "$ANDROID_NDK_HOME/" -name "aarch64-linux-android31-clang"))
PATH=$PATH:$NDK_TOOLCHAIN_BINS

#rm -rf build_win64
mkdir -p build_android_aarch64 && cd build_android_aarch64
OPENJKDF2_BUILD_DIR=$(pwd)

# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

export SDL2_DIR="$OPENJKDF2_BUILD_DIR/SDL2-2.26.4"
export OPENJKDF2_SDL2_PATH="$SDL2_DIR"
export OPENJKDF2_SDL2_LIBRARY="$OPENJKDF2_BUILD_DIR/libSDL2.so"
export OPENJKDF2_SDL2_INCLUDE_DIR="$SDL2_DIR/include"

export OPENJKDF2_SDL2_MIXER_PATH="$OPENJKDF2_BUILD_DIR/SDL2_mixer-2.6.3"
export OPENJKDF2_SDL2_MIXER_LIBRARY="$OPENJKDF2_BUILD_DIR/libSDL2_mixer.so"
export OPENJKDF2_SDL2_MIXER_INCLUDE_DIR="$OPENJKDF2_SDL2_MIXER_PATH/include"

cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_android_aarch64.cmake && make -j10 openjkdf2-armv8a
cd ..

cd packaging/android-project
mkdir -p app/src/main/jniLibs
mkdir -p app/src/main/jniLibs/arm64-v8a
cp $OPENJKDF2_SDL2_LIBRARY app/src/main/jniLibs/arm64-v8a
cp $OPENJKDF2_SDL2_MIXER_LIBRARY app/src/main/jniLibs/arm64-v8a
cp $OPENJKDF2_BUILD_DIR/libopenjkdf2-armv8a.so app/src/main/jniLibs/arm64-v8a/libmain.so
./gradlew assembleDebug
./gradlew installDebug
cd ../..
#adb push wasm_out/jk1 /storage/self/primary/Android/data/org.openjkdf2.app/files/
#adb push wasm_out/mots /storage/self/primary/Android/data/org.openjkdf2.app/files/
adb shell am start -n org.openjkdf2.app/.GameActivity
