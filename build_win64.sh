#!/bin/bash
#make flex/flex
#make byacc/yacc

export OPENJKDF2_RELEASE_COMMIT="$(git log -1 --format="%H")" \
       OPENJKDF2_RELEASE_COMMIT_SHORT="$(git rev-parse --short=8 HEAD)" &&
# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH &&

#rm -rf build_win64
mkdir -p build_win64 && pushd build_win64 &&

cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_mingw.cmake &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
(make -j $(nproc) PROTOC || make -j1 PROTOC) && 
make -j $(nproc) openjkdf2-64 &&
popd &&
./scripts/helper_CopyMinGWDLLs.sh
