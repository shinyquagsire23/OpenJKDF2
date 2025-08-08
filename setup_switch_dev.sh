#!/bin/bash

# OpenJKDF2 Switch Installation Helper
# This script helps set up the Switch development environment for OpenJKDF2

echo "OpenJKDF2 Switch Build Setup"
echo "============================="
echo ""

# Check if devkitPro is installed
if [ -z "$DEVKITPRO" ]; then
    echo "❌ DEVKITPRO environment variable not set!"
    echo ""
    echo "Please install devkitPro first:"
    echo "1. Visit https://devkitpro.org/wiki/Getting_Started"
    echo "2. Follow the installation instructions for your OS"
    echo "3. Make sure DEVKITPRO environment variable is set"
    echo ""
    exit 1
else
    echo "✅ DEVKITPRO found at: $DEVKITPRO"
fi

# Check if devkitA64 exists
if [ ! -d "$DEVKITPRO/devkitA64" ]; then
    echo "❌ devkitA64 not found!"
    echo ""
    echo "Please install the Switch development tools:"
    echo "  sudo dkp-pacman -S switch-dev"
    echo ""
    exit 1
else
    echo "✅ devkitA64 found"
fi

# Check if libnx exists
if [ ! -d "$DEVKITPRO/libnx" ]; then
    echo "❌ libnx not found!"
    echo ""
    echo "Please install libnx:"
    echo "  sudo dkp-pacman -S libnx"
    echo ""
    exit 1
else
    echo "✅ libnx found"
fi

# Check for required portlibs
echo ""
echo "Checking for required portlibs..."

REQUIRED_LIBS=("switch-sdl2" "switch-sdl2_mixer" "switch-libpng" "switch-zlib" "switch-physfs" "switch-openal-soft")
MISSING_LIBS=()

for lib in "${REQUIRED_LIBS[@]}"; do
    if dkp-pacman -Q "$lib" &>/dev/null; then
        echo "✅ $lib is installed"
    else
        echo "❌ $lib is missing"
        MISSING_LIBS+=("$lib")
    fi
done

if [ ${#MISSING_LIBS[@]} -gt 0 ]; then
    echo ""
    echo "Missing libraries detected. Installing..."
    echo "sudo dkp-pacman -S ${MISSING_LIBS[*]}"
    sudo dkp-pacman -S "${MISSING_LIBS[@]}"
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install required libraries"
        exit 1
    fi
fi

echo ""
echo "✅ All dependencies are installed!"
echo ""
echo "You can now build OpenJKDF2 for Switch by running:"
echo "  ./build_switch.sh"
echo ""
echo "Make sure you have your JKDF2 game files ready to copy to the Switch SD card:"
echo "  /switch/openjkdf2/"
echo ""
