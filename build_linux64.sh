#!/bin/bash

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H") &&
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD) &&

mkdir -p build_linux64 && pushd build_linux64 &&

cmake .. &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
make -j $(nproc) openjkdf2 &&
popd
