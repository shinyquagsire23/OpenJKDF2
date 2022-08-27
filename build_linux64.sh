#!/bin/zsh

mkdir -p build_linux64 && cd build_linux64

if [ ! -f build_protoc/protoc ]; then
    mkdir -p build_protoc && cd build_protoc
    cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
    make -j10 protoc
    cd ..
fi

if [ ! -f build_protobuf/libprotobuf.so ]; then
    mkdir -p build_protobuf && cd build_protobuf
    cmake -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
    make -j10 install
    cd ..
fi

if [ ! -f build_gns/bin/libGameNetworkingSockets.so ]; then
    mkdir -p build_gns && cd build_gns
    GNS_BUILD=$(pwd)
    cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../build_protobuf/include -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc $GNS_BUILD/../../3rdparty/GameNetworkingSockets
    make -j10
    cd ..
fi

cmake .. &&
make -j10 &&
cd ..