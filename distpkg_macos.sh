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

mkdir -p build_darwin_x86_64 && cd build_darwin_x86_64 &&

# Begin ugghhhhhhh
mkdir -p build_protoc && cd build_protoc
cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
make -j10 protoc
cd ..

mkdir -p build_protobuf && cd build_protobuf
cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
make -j10 install
cd ..

mkdir -p build_gns && cd build_gns
GNS_BUILD=$(pwd)
export PKG_CONFIG_PATH_OLD=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD:/usr/local/opt/openssl@1.1/lib/pkgconfig
cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../build_protobuf/include -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc $GNS_BUILD/../../3rdparty/GameNetworkingSockets
make -j10
cd ..

mkdir -p build_physfs && cd build_physfs
PHYSFS_BUILD=$(pwd)
cmake -DCMAKE_OSX_ARCHITECTURES="x86_64" -DCMAKE_BUILD_TYPE=Release -DPHYSFS_ARCHIVE_GRP=FALSE -DPHYSFS_ARCHIVE_WAD=FALSE -DPHYSFS_ARCHIVE_HOG=FALSE -DPHYSFS_ARCHIVE_MVL=FALSE -DPHYSFS_ARCHIVE_QPAK=FALSE -DPHYSFS_ARCHIVE_SLB=FALSE -DPHYSFS_ARCHIVE_VDF=FALSE $PHYSFS_BUILD/../../3rdparty/physfs
make -j10
cd ..
# End ugghhhhhhh

cmake .. -DPLAT_MACOS_X86_64=true &&
cmake .. -DPLAT_MACOS_X86_64=true &&
make -j10 &&
cd .. &&

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD

#
# ARM64
#

mkdir -p build_darwin64 && cd build_darwin64 &&

# Begin ugghhhhhhh
mkdir -p build_protoc && cd build_protoc
cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
make -j10 protoc
cd ..

mkdir -p build_protobuf && cd build_protobuf
cmake -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
make -j10 install
cd ..

mkdir -p build_gns && cd build_gns
GNS_BUILD=$(pwd)
export PKG_CONFIG_PATH_OLD=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH_OLD:/opt/homebrew/opt/openssl@1.1/lib/pkgconfig
cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../build_protobuf/include -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc $GNS_BUILD/../../3rdparty/GameNetworkingSockets
make -j10
cd ..

mkdir -p build_physfs && cd build_physfs
PHYSFS_BUILD=$(pwd)
cmake -DCMAKE_BUILD_TYPE=Release -DPHYSFS_ARCHIVE_GRP=FALSE -DPHYSFS_ARCHIVE_WAD=FALSE -DPHYSFS_ARCHIVE_HOG=FALSE -DPHYSFS_ARCHIVE_MVL=FALSE -DPHYSFS_ARCHIVE_QPAK=FALSE -DPHYSFS_ARCHIVE_SLB=FALSE -DPHYSFS_ARCHIVE_VDF=FALSE $PHYSFS_BUILD/../../3rdparty/physfs
make -j10
cd ..
# End ugghhhhhhh

cmake .. &&
make -j10 &&
cd .. &&

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