#!/bin/bash

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

# Check if devkitPro is installed
if [ -z "$DEVKITPRO" ]; then
    echo "DEVKITPRO environment variable not set!"
    echo "Please install devkitPro and set DEVKITPRO to the installation path"
    echo "Visit https://devkitpro.org/wiki/Getting_Started for installation instructions"
    exit 1
fi

if [ ! -d "$DEVKITPRO/devkitA64" ]; then
    echo "devkitA64 not found in $DEVKITPRO"
    echo "Please install devkitA64 using: sudo dkp-pacman -S switch-dev"
    exit 1
fi

mkdir -p build_switch && pushd build_switch
OPENJKDF2_BUILD_DIR=$(pwd)

# Prevent macOS headers from getting linked in
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

EXPERIMENTAL_FIXED_POINT=0
DEBUG_QOL_CHEATS=1

export PORTLIBS="/opt/devkitpro/portlibs/switch"
export OPENJKDF2_SDL2_LIBRARY="$PORTLIBS/lib/libSDL2.so"
export OPENJKDF2_SDL2_INCLUDE_DIR="$PORTLIBS/include/SDL2"

export OPENJKDF2_SDL2_MIXER_LIBRARY="$PORTLIBS/lib/libSDL2_mixer.so"
export OPENJKDF2_SDL2_MIXER_INCLUDE_DIR="$PORTLIBS/include/SDL2"

echo "Building OpenJKDF2 for Nintendo Switch..."
echo "Using devkitPro at: $DEVKITPRO"


#EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_switch.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 &&
EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS cmake .. --toolchain $DEVKITPRO/cmake/Switch.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 &&
(EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j $(nproc) openjkdf2 || EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j1 openjkdf2)

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Check what files were actually created
echo "Files created in build directory:"
ls -la *.elf* 2>/dev/null || echo "No .elf files found"
ls -la lib*.a 2>/dev/null || echo "No .a files found"

popd

echo "Build completed successfully!"
echo "Check build_switch/ directory for output files"
echo ""
echo "To install on your Switch:"
echo "1. Copy openjkdf2.nro to /switch/ on your SD card"
echo "2. Copy your JKDF2 game files to /switch/openjkdf2/ on your SD card"
echo "3. Launch via Homebrew Launcher"
