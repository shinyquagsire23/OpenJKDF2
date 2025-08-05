#!/bin/bash

# Build script for SDL2 Switch test

echo "=== Building SDL2 Switch Test ==="

# Check if DEVKITPRO is set
if [ -z "$DEVKITPRO" ]; then
    echo "Error: DEVKITPRO environment variable is not set!"
    echo "Please install devkitPro and source the environment setup."
    exit 1
fi

# Clean previous build
rm -rf build_sdl_test

# Create build directory
mkdir -p build_sdl_test
cd build_sdl_test

# Configure with CMake
echo "Configuring with CMake..."
cmake --project-file ./CMakeLists_sdl_test.txt -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..
if [ $? -ne 0 ]; then
    echo "CMake configuration failed!"
    exit 1
fi

# Build
echo "Building..."
make VERBOSE=1

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Build completed successfully!"
echo "NRO file should be located at: build_sdl_test/switch_sdl_test.nro"
