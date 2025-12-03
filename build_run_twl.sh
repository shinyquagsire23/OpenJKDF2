#!/bin/bash

./build_twl_podman.sh

if [ $? -ne 0 ]; then
    exit -1
fi

if [ "$(whoami)" == "maxamillion" ]; then
    echo "Starting..." && \
    pkill -9 melonDS ; pkill -9 melonDS ; /Applications/melonDS.app/Contents/MacOS/melonDS build_nintendo_dsi/openjkdf2.nds
fi