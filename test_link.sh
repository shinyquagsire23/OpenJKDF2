#!/bin/bash

# Script to manually test linking and show all errors

DEVKITPRO=/opt/devkitpro
DEVKITA64=$DEVKITPRO/devkitA64
LIBNX=$DEVKITPRO/libnx
PORTLIBS=$DEVKITPRO/portlibs/switch

CC=$DEVKITA64/bin/aarch64-none-elf-gcc
CXX=$DEVKITA64/bin/aarch64-none-elf-g++

echo "=== Testing basic compilation and linking ==="

# Test 1: Simple hello world without any libraries
echo "Test 1: Basic hello world"
cat > test_basic.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello Switch!\n");
    return 0;
}
EOF

$CC -specs=$LIBNX/switch.specs \
    -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC \
    -I$LIBNX/include \
    -L$LIBNX/lib \
    test_basic.c -lnx -o test_basic.elf \
    -Wl,--verbose -v 2>&1 | tee test1.log

echo "Exit code: $?"
echo ""

# Test 2: With SDL2
echo "Test 2: With SDL2"
cat > test_sdl.c << 'EOF'
#include <stdio.h>
#include <SDL2/SDL.h>
int main() {
    SDL_Init(SDL_INIT_VIDEO);
    printf("SDL initialized\n");
    SDL_Quit();
    return 0;
}
EOF

$CC -specs=$LIBNX/switch.specs \
    -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC \
    -I$LIBNX/include -I$PORTLIBS/include \
    -L$LIBNX/lib -L$PORTLIBS/lib \
    test_sdl.c -lSDL2 -lnx -o test_sdl.elf \
    -Wl,--verbose -v -Wl,--unresolved-symbols=report-all 2>&1 | tee test2.log

echo "Exit code: $?"
echo ""

# Test 3: Check what symbols are missing
echo "Test 3: Symbol analysis"
if [ -f test_sdl.elf ]; then
    echo "SDL test succeeded, checking symbols:"
    $DEVKITA64/bin/aarch64-none-elf-nm test_sdl.elf | grep -i undefined || echo "No undefined symbols"
else
    echo "SDL test failed, checking for undefined symbols in object file:"
    $CC -specs=$LIBNX/switch.specs \
        -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC \
        -I$LIBNX/include -I$PORTLIBS/include \
        -c test_sdl.c -o test_sdl.o
    
    $DEVKITA64/bin/aarch64-none-elf-nm test_sdl.o | grep -i undefined
    
    echo "Now attempting to link with more verbose output:"
    $CC -specs=$LIBNX/switch.specs \
        -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC \
        -L$LIBNX/lib -L$PORTLIBS/lib \
        test_sdl.o -lSDL2 -lnx -o test_sdl.elf \
        -Wl,--verbose -Wl,--unresolved-symbols=report-all -Wl,--warn-unresolved-symbols 2>&1 | tee test3.log
fi

echo ""
echo "=== Summary ==="
echo "Check test1.log, test2.log, and test3.log for detailed output"
echo "Look for lines containing 'undefined', 'error', or 'unresolved'"
