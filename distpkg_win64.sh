#!/bin/sh

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

rm -rf win64-package
rm -f win64-debug.zip

rm -rf build_win64

mkdir -p build_win64 && pushd build_win64

# Begin ughhhhh

# Prevent macOS headers from getting linked in
SDKROOT=""
MACOSX_DEPLOYMENT_TARGET=""
CPLUS_INCLUDE_PATH=""
C_INCLUDE_PATH=""

# End ughhhh

cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_mingw.cmake &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
(make -j $(nproc) PROTOC || make -j1 PROTOC) && 
make -j $(nproc) openjkdf2-64
if [ $? -ne 0 ]; then
    exit -1
fi
popd

./scripts/helper_CopyMinGWDLLs.sh

mkdir -p win64-package
cp build_win64/*.dll win64-package
cp build_win64/*.exe win64-package

#make -f Makefile.win64 clean
#make -f Makefile.win64 -j10

#cp -r resource win64-package
rm -f win64-debug.zip
cd win64-package ; zip -r ../win64-debug.zip . ; cd ..

rm -rf build_win64
rm -rf win64-package