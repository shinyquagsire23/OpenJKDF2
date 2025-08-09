# OpenJKDF2 Nintendo Switch Build Guide

This guide explains how to build OpenJKDF2 for Nintendo Switch using devkitPro.

## Prerequisites

1. **devkitPro Installation**
   - Install devkitPro from https://devkitpro.org/wiki/Getting_Started
   - Make sure the `DEVKITPRO` environment variable is set

2. **Required Packages**
   - `switch-dev` (includes devkitA64 toolchain)
   - `libnx` (Nintendo Switch library)
   - `switch-sdl2` (SDL2 for Switch)
   - `switch-sdl2_mixer` (SDL2_mixer for Switch)
   - `switch-libpng` (PNG library)
   - `switch-zlib` (Compression library)
   - `switch-physfs` (File system abstraction)

## Quick Setup

1. Run the setup script to check dependencies:
   ```bash
   ./setup_switch_dev.sh
   ```

2. Build OpenJKDF2 for Switch:
   ```bash
   ./build_switch.sh
   ```

## Manual Setup

If you prefer to set up manually:

```bash
# Install required packages
sudo dkp-pacman -S switch-dev libnx switch-sdl2 switch-sdl2_mixer switch-libpng switch-zlib switch-physfs

# Build
mkdir -p build_switch && cd build_switch
cmake .. --toolchain ../cmake_modules/toolchain_switch.cmake
make -j$(nproc) openjkdf2.nro
```

## Installation on Switch

1. Copy `build_switch/openjkdf2.nro` to `/switch/` on your Switch SD card
2. Create a directory `/switch/openjkdf2/` on your SD card
3. Copy your JKDF2 game files to `/switch/openjkdf2/`:
   - `JK.EXE`
   - `episode/` directory with GOB files
   - `resource/` directory with game resources
   - `MUSIC/` directory (optional, for soundtrack)

## Directory Structure on Switch

```
/switch/
├── openjkdf2.nro           # The homebrew executable
└── openjkdf2/              # Game data directory
    ├── JK.EXE
    ├── episode/
    │   ├── JK1.gob
    │   ├── JK1CTF.gob
    │   └── JK1MP.gob
    ├── resource/
    │   ├── Res1hi.gob
    │   ├── Res2.gob
    │   ├── jk_.cd
    │   └── video/
    └── MUSIC/              # Optional soundtrack files
        ├── Track12.ogg
        ├── Track13.ogg
        └── ...
```

## Launch

Launch OpenJKDF2 through the Homebrew Launcher on your Switch.

## Notes

- This is homebrew software and requires a Switch capable of running homebrew
- The Switch must be able to run unsigned code (custom firmware required)
- Game performance may vary depending on the scene complexity
- Save files are stored in the Switch's internal storage under the homebrew data directory

## Troubleshooting

- **Build fails with missing libraries**: Run `./setup_switch_dev.sh` to install missing dependencies
- **Runtime crashes**: Ensure all game files are present and have correct case-sensitive filenames
- **No sound**: Check that SDL2_mixer is properly installed and audio files are in the correct format
- **Poor performance**: Try reducing resolution or graphics settings (if available in game menus)

## Controls

The default controls should work with Switch Pro Controller or Joy-Cons. Control mapping may be configurable in the game's settings menu.
