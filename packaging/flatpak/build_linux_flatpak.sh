#!/bin/bash

mkdir -p build_linux && cd build_linux

if [ ! -f build_protoc/protoc ]; then
    mkdir -p build_protoc && cd build_protoc
    cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    make -j10 protoc
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    cd ..
fi

if [ ! -f libprotobuf.so.3.21.4.0 ]; then
    mkdir -p build_protobuf && cd build_protobuf
    cmake -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    make -j10 install
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    cd ..
    cp build_protobuf/libprotobuf.so.3.21.4.0 .
fi

if [ ! -f libGameNetworkingSockets.so ]; then
    mkdir -p build_gns && cd build_gns
    GNS_BUILD=$(pwd)
    cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../build_protobuf/include -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc $GNS_BUILD/../../3rdparty/GameNetworkingSockets
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    make -j10
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    cd ..
    cp build_gns/bin/libGameNetworkingSockets.so .
fi

if [ ! -f build_physfs/libphysfs.a ]; then
    mkdir -p build_physfs && cd build_physfs
    PHYSFS_BUILD=$(pwd)
    cmake -DCMAKE_BUILD_TYPE=Release -DPHYSFS_ARCHIVE_GRP=FALSE -DPHYSFS_ARCHIVE_WAD=FALSE -DPHYSFS_ARCHIVE_HOG=FALSE -DPHYSFS_ARCHIVE_MVL=FALSE -DPHYSFS_ARCHIVE_QPAK=FALSE -DPHYSFS_ARCHIVE_SLB=FALSE -DPHYSFS_ARCHIVE_VDF=FALSE $PHYSFS_BUILD/../../3rdparty/physfs
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    make -j10
    (($? != 0)) && { printf '%s\n' "Command exited with non-zero"; exit 1; }
    cd ..
fi

cmake -DCMAKE_INSTALL_PREFIX=$FLATPAK_DEST .. &&
make -j10 &&
cd .. &&
mkdir -p $FLATPAK_DEST/share/applications/ &&
mkdir -p $FLATPAK_DEST/bin &&
mkdir -p $FLATPAK_DEST/share/metainfo &&
cp build_linux/openjkdf2 $FLATPAK_DEST/bin &&
cp build_linux/*.so $FLATPAK_DEST/lib &&
cp build_linux/libprotobuf.so.3.21.4.0 $FLATPAK_DEST/lib &&
cp packaging/flatpak/org.openjkdf2.OpenJKDF2.desktop $FLATPAK_DEST/share/applications/ &&
cp packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml $FLATPAK_DEST/share/metainfo/ &&
bash packaging/flatpak/copy_icons.sh packaging/flatpak/icons
