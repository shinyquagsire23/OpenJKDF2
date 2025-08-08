# OpenJKDF2 Nintendo Switch Minimal Test

This is a minimal SDL2 example for Nintendo Switch that demonstrates basic graphics rendering without the complexity of the full OpenJKDF2 engine.

## What this test does

- Initializes SDL2 on Nintendo Switch
- Creates a fullscreen window
- Renders animated colored rectangles
- Displays RGB test pattern
- Shows animated graphics
- Responds to + button to exit
- Provides console output for debugging

## Files

- `src/main_switch_simple.c` - Minimal SDL2 test application
- `Makefile_switch_simple` - Makefile for building with devkitPro
- `CMakeLists_switch_simple.txt` - CMake build file (alternative)
- `build_switch_simple.sh` - Build script

## Prerequisites

1. **devkitPro**: Install devkitPro and set up the environment
   ```bash
   export DEVKITPRO=/opt/devkitpro
   export PATH=$DEVKITPRO/tools/bin:$PATH
   ```

2. **libnx**: Should be included with devkitPro Switch development packages

3. **SDL2**: Install SDL2 for Switch
   ```bash
   sudo dkp-pacman -S switch-sdl2
   ```

## Building

### Method 1: Using Makefile (Recommended)
```bash
cd /path/to/OpenJKDF2
make -f Makefile_switch_simple
```

### Method 2: Using build script
```bash
cd /path/to/OpenJKDF2
./build_switch_simple.sh
```

### Method 3: Using CMake
```bash
cd /path/to/OpenJKDF2
mkdir build_switch_simple
cd build_switch_simple
cmake -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/Switch.cmake -f ../CMakeLists_switch_simple.txt ..
make
```

## Running

1. Copy the generated `.nro` file to the `/switch/` directory on your Switch's SD card
2. Launch the Homebrew Launcher on your modded Nintendo Switch
3. Navigate to and launch the OpenJKDF2 Simple Test
4. You should see:
   - Animated background color
   - Moving white rectangle
   - RGB test pattern (red, green, blue squares)
   - Yellow animated dots
   - Console output showing frame counts

## Controls

- **+ Button**: Exit the application

## Troubleshooting

### If you see "SDL could not initialize" error:
- Check that SDL2 for Switch is properly installed
- Verify your devkitPro environment is set up correctly
- Make sure you're running on a modded Switch with homebrew support

### If the screen stays black:
- Check the console output in the Homebrew Launcher
- Look for SDL or renderer creation errors
- Verify the Switch has sufficient free memory

### Build errors:
- Ensure `DEVKITPRO` environment variable is set
- Install required packages: `sudo dkp-pacman -S switch-dev`
- Check that all file paths are correct

## Differences from main OpenJKDF2

This minimal test removes all the complex dependencies and game logic to isolate potential issues:

- No complex memory management
- No file I/O operations  
- No audio systems
- No networking
- No game engine components
- Simple SDL2 graphics only
- Minimal error handling with detailed console output

If this minimal test works, you can gradually add back components from the full OpenJKDF2 to identify what's causing the crashes.

## Next Steps

If this minimal test works correctly:
1. Try adding basic file I/O 
2. Add audio initialization
3. Add memory management systems
4. Gradually integrate OpenJKDF2 components

If this test fails, the issue is likely with:
1. Basic SDL2 setup
2. devkitPro environment
3. Switch homebrew environment
4. Hardware compatibility
