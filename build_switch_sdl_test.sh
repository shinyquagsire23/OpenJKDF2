#!/bin/bash

# Build script for Switch SDL2 test
set -e

echo "Building Switch SDL2 test..."

# Check devkitPro environment
if [ -z "$DEVKITPRO" ]; then
    echo "Error: DEVKITPRO environment variable not set"
    exit 1
fi

# Create build directory
mkdir -p build_switch_sdl_test
cd build_switch_sdl_test

# Configure with CMake
cmake --project-file=./CMakeLists_sdl_test.txt -DCMAKE_BUILD_TYPE=Release --toolchain $DEVKITPRO/cmake/Switch.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..

# Build the project
make -j$(nproc)

echo "Build complete. Output files:"
ls -la *.nro *.elf 2>/dev/null || echo "No output files found"
