#!/bin/sh
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

NDK_TOOLCHAIN_BINS=$(dirname $(find "$ANDROID_NDK_HOME/" -name "aarch64-linux-android31-clang"))
PATH=$PATH:$NDK_TOOLCHAIN_BINS

#rm -rf build_win64
mkdir -p build_android_aarch64 && cd build_android_aarch64
OPENJKDF2_BUILD_DIR=$(pwd)

# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

(cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_android_aarch64.cmake || cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_android_aarch64.cmake)
if [ $? -ne 0 ]; then
    exit -1
fi

make -j1 openjkdf2-armv8a
make -j1 openjkdf2-armv8a
if [ $? -ne 0 ]; then
    exit -1
fi

cd ..

pushd packaging/android-project
mkdir -p app/src/main/jniLibs && 
mkdir -p app/src/main/jniLibs/arm64-v8a && 
cp $OPENJKDF2_BUILD_DIR/libopenjkdf2-armv8a.so app/src/main/jniLibs/arm64-v8a/libmain.so && 
cp $OPENJKDF2_BUILD_DIR/openal/libopenal.so app/src/main/jniLibs/arm64-v8a/libopenal.so && 
cp $OPENJKDF2_BUILD_DIR/SDL/libSDL2.so app/src/main/jniLibs/arm64-v8a/libSDL2.so && 
cp $OPENJKDF2_BUILD_DIR/SDL_mixer/libSDL2_mixer.so app/src/main/jniLibs/arm64-v8a/libSDL2_mixer.so && 
./gradlew assembleDebug && 
./gradlew installDebug && 
popd

cp $OPENJKDF2_BUILD_DIR/../packaging/android-project/app/build/outputs/apk/debug/app-debug.apk android-OpenJKDF2-arm64-v8a.apk

