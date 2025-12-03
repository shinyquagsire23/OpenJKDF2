#!/bin/bash

rm -rf build_android_aarch64

./build_android.sh
if [ $? -ne 0 ]; then
    exit -1
fi