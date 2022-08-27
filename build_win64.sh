#!/bin/zsh
#make flex/flex
#make byacc/yacc

rm -rf build_win64
mkdir -p build_win64 && cd build_win64

mkdir -p build_protoc && cd build_protoc
cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
make -j10 protoc
cd ..

mkdir -p build_protobuf && cd build_protobuf
PB_BUILD=$(pwd)
cmake --toolchain ../../cmake_modules/mingw_toolchain.cmake -DCMAKE_INSTALL_PREFIX=$PB_BUILD -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
make -j10 install
cd ..

mkdir -p build_gns && cd build_gns
GNS_BUILD=$(pwd)
cmake --toolchain $GNS_BUILD/../../cmake_modules/mingw_toolchain.cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIRS=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_INCLUDE_DIR2=$GNS_BUILD/../../3rdparty/protobuf/third_party/abseil-cpp -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc -D USE_CRYPTO="BCrypt" $GNS_BUILD/../../3rdparty/GameNetworkingSockets
make -j10
cd ..

#cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake -D USE_CRYPTO="BCrypt" -Dprotobuf_BUILD_TESTS=OFF
cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake && make -j10 openjkdf2-64
cd ..

./scripts/helper_CopyMinGWDLLs.sh