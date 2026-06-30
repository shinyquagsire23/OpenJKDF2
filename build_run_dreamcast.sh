#!/bin/bash

./build_dreamcast.sh

if [ $? -ne 0 ]; then
    exit -1
fi

if [ "$(whoami)" == "maxamillion" ]; then
    echo "Starting..." && \
    pkill -9 Flycast ; pkill -9 Flycast ; /Applications/Flycast.app/Contents/MacOS/Flycast build_dreamcast/openjkdf2.cdi
    #pkill -9 redream ; pkill -9 redream ; /Applications/redream.app/Contents/MacOS/redream build_dreamcast/openjkdf2.elf
fi