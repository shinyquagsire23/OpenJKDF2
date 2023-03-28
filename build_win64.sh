#!/bin/sh
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT="$(git log -1 --format="%H")"
export OPENJKDF2_RELEASE_COMMIT_SHORT="$(git rev-parse --short=8 HEAD)"
# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

#rm -rf build_win64
mkdir -p build_win64 && pushd build_win64

if [ ! -f build_protoc/protoc ]; then
    mkdir -p build_protoc && pushd build_protoc
    cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
    make -j protoc
    popd
fi

if [ ! -f build_protobuf/libprotobuf.dll ]; then
    mkdir -p build_protobuf && pushd build_protobuf
    PB_BUILD=$(pwd)
    cmake --toolchain ../../cmake_modules/toolchain_mingw.cmake -DCMAKE_INSTALL_PREFIX="$PB_BUILD" -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf
    make -j install
    popd
fi

if [ ! -f build_gns/bin/libGameNetworkingSockets.dll ]; then
    mkdir -p build_gns && pushd build_gns
    GNS_BUILD=$(pwd)
    cmake --toolchain "$GNS_BUILD/../../cmake_modules/toolchain_mingw.cmake" -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIRS="$GNS_BUILD/../../3rdparty/protobuf/src" -DProtobuf_INCLUDE_DIR="$GNS_BUILD/../../3rdparty/protobuf/src" -DProtobuf_INCLUDE_DIR2="$GNS_BUILD/../../3rdparty/protobuf/third_party/abseil-cpp" -DProtobuf_PROTOC_EXECUTABLE="$GNS_BUILD/../build_protoc/protoc" -DUSE_CRYPTO="BCrypt" "$GNS_BUILD/../../3rdparty/GameNetworkingSockets"
    make -j
    popd
fi

if [ ! -f build_physfs/libphysfs.a ]; then
    mkdir -p build_physfs && pushd build_physfs
    PHYSFS_BUILD=$(pwd)
    cmake --toolchain "$PHYSFS_BUILD/../../cmake_modules/toolchain_mingw.cmake" -DCMAKE_BUILD_TYPE=Release -DPHYSFS_ARCHIVE_GRP=FALSE -DPHYSFS_ARCHIVE_WAD=FALSE -DPHYSFS_ARCHIVE_HOG=FALSE -DPHYSFS_ARCHIVE_MVL=FALSE -DPHYSFS_ARCHIVE_QPAK=FALSE -DPHYSFS_ARCHIVE_SLB=FALSE -DPHYSFS_ARCHIVE_VDF=FALSE "$PHYSFS_BUILD/../../3rdparty/physfs"
    make -j
    popd
fi

#cmake .. --toolchain ../cmake_modules/toolchain_mingw.cmake -D USE_CRYPTO="BCrypt" -Dprotobuf_BUILD_TESTS=OFF
cmake .. --toolchain ../cmake_modules/toolchain_mingw.cmake &&
make -j openjkdf2-64 &&
popd &&
./scripts/helper_CopyMinGWDLLs.sh
