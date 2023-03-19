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

if [ ! -f build_protoc/protoc ]; then
    mkdir -p build_protoc && cd build_protoc
    #cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
    #make -j10 protoc
    cd ..
fi

# Prevent macOS headers from getting linked in
SDKROOT=""
MACOSX_DEPLOYMENT_TARGET=""
CPLUS_INCLUDE_PATH=""
C_INCLUDE_PATH=""

if [ ! -f libSDL2.so ]; then
    rm -f SDL2-2.26.4.zip
    wget https://www.libsdl.org/release/SDL2-2.26.4.zip
    unzip -q SDL2-2.26.4.zip && rm -f SDL2-2.26.4.zip

    cd SDL2-2.26.4/build-scripts/
    ./androidbuildlibs.sh APP_ABI="arm64-v8a" APP_PLATFORM=android-31
    cd "$OPENJKDF2_BUILD_DIR"
    cp SDL2-2.26.4/build/android/lib/arm64-v8a/libSDL2.so .
fi

export SDL2_DIR="$OPENJKDF2_BUILD_DIR/SDL2-2.26.4"
export OPENJKDF2_SDL2_PATH="$SDL2_DIR"
export OPENJKDF2_SDL2_LIBRARY="$OPENJKDF2_BUILD_DIR/libSDL2.so"
export OPENJKDF2_SDL2_INCLUDE_DIR="$SDL2_DIR/include"

if [ ! -d SDL2_mixer-2.6.3 ]; then
    rm -f SDL2_mixer-2.6.3.zip
    rm -rf SDL2_mixer-2.6.3
    wget https://github.com/libsdl-org/SDL_mixer/releases/download/release-2.6.3/SDL2_mixer-2.6.3.zip
    unzip -q SDL2_mixer-2.6.3.zip && rm -f SDL2_mixer-2.6.3.zip
fi

if [ ! -f libSDL2_mixer.so ]; then
    cd $OPENJKDF2_BUILD_DIR/SDL2_mixer-2.6.3
    ./external/download.sh
    mkdir -p build && cd build
    cmake --toolchain $OPENJKDF2_BUILD_DIR/../cmake_modules/toolchain_android_aarch64.cmake -DSDL2MIXER_VENDORED=ON ..
    make -j10 SDL2_mixer

    #cd SDL2-2.26.4/build-scripts/
    #./androidbuildlibs.sh APP_ABI="arm64-v8a" APP_PLATFORM=android-31
    cd "$OPENJKDF2_BUILD_DIR"
    cp SDL2_mixer-2.6.3/build/libSDL2_mixer.so .
fi

export OPENJKDF2_SDL2_MIXER_PATH="$OPENJKDF2_BUILD_DIR/SDL2_mixer-2.6.3"
export OPENJKDF2_SDL2_MIXER_LIBRARY="$OPENJKDF2_BUILD_DIR/libSDL2_mixer.so"
export OPENJKDF2_SDL2_MIXER_INCLUDE_DIR="$OPENJKDF2_SDL2_MIXER_PATH/include"

if [ ! -f libprotobuf.so.3.21.4.0 ]; then
    mkdir -p build_protobuf && cd build_protobuf
    PB_BUILD=$(pwd)
    #cmake --toolchain ../../cmake_modules/toolchain_android_aarch64.cmake -DCMAKE_INSTALL_PREFIX=$PB_BUILD -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
    #make -j10 install
    cd $OPENJKDF2_BUILD_DIR
    #cp build_protobuf/libprotobuf.so.3.21.4.0 .
fi

if [ ! -f libGameNetworkingSockets.so ]; then
    mkdir -p build_gns && cd build_gns
    GNS_BUILD=$(pwd)
    #cmake --toolchain $GNS_BUILD/../../cmake_modules/toolchain_android_aarch64.cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIRS=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../../3rdparty/protobuf/third_party/abseil-cpp -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc $GNS_BUILD/../../3rdparty/GameNetworkingSockets
    #make -j10
    cd $OPENJKDF2_BUILD_DIR
    #cp build_gns/bin/libGameNetworkingSockets.so .
fi

if [ ! -f build_physfs/libphysfs.a ]; then
    mkdir -p build_physfs && cd build_physfs
    PHYSFS_BUILD=$(pwd)
    #cmake --toolchain $PHYSFS_BUILD/../../cmake_modules/toolchain_android_aarch64.cmake -DCMAKE_BUILD_TYPE=Release -DPHYSFS_ARCHIVE_GRP=FALSE -DPHYSFS_ARCHIVE_WAD=FALSE -DPHYSFS_ARCHIVE_HOG=FALSE -DPHYSFS_ARCHIVE_MVL=FALSE -DPHYSFS_ARCHIVE_QPAK=FALSE -DPHYSFS_ARCHIVE_SLB=FALSE -DPHYSFS_ARCHIVE_VDF=FALSE $PHYSFS_BUILD/../../3rdparty/physfs
    #make -j10
    cd $OPENJKDF2_BUILD_DIR
fi

cmake .. --toolchain ../cmake_modules/toolchain_android_aarch64.cmake && make -j10 openjkdf2-armv8a
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