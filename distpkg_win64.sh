#!/bin/zsh

rm -rf win64-package
rm -f win64-debug.zip

rm -rf build_win64

mkdir -p build_win64 && cd build_win64

# Begin ughhhhh
mkdir -p build_protoc && cd build_protoc
cmake -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF ../../3rdparty/protobuf/cmake
make -j10 protoc
cd ..

mkdir -p build_protobuf && cd build_protobuf
cmake --toolchain ../../cmake_modules/mingw_toolchain.cmake -DCMAKE_INSTALL_PREFIX=. -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON ../../3rdparty/protobuf/cmake
make -j10 install
cd ..

mkdir -p build_gns && cd build_gns
GNS_BUILD=$(pwd)
cmake --toolchain $GNS_BUILD/../../cmake_modules/mingw_toolchain.cmake -DCMAKE_BUILD_TYPE=Release -DProtobuf_USE_STATIC_LIBS=ON -DProtobuf_LIBRARIES="-L$GNS_BUILD/../build_protobuf/lib" -DProtobuf_LIBRARIES_PATH="$GNS_BUILD/../build_protobuf/lib" -DProtobuf_INCLUDE_DIRS=$GNS_BUILD/../../3rdparty/protobuf/src -DProtobuf_PROTOC_EXECUTABLE=$GNS_BUILD/../build_protoc/protoc -D USE_CRYPTO="BCrypt" $GNS_BUILD/../../3rdparty/GameNetworkingSockets
make -j10
cd ..
# End ughhhh

cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake &&
make -j10 &&
cd .. &&

./scripts/helper_CopyMinGWDLLs.sh

mkdir -p win64-package
cp build_win64/*.dll win64-package
cp build_win64/*.exe win64-package

#make -f Makefile.win64 clean
#make -f Makefile.win64 -j10

#cp -r resource win64-package
rm -f win64-debug.zip
cd win64-package ; zip -r ../win64-debug.zip . ; cd ..

#make -f Makefile.win64 clean
rm -rf build_win64
rm -rf win64-package