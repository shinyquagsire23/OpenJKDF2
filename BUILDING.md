## Building OpenJKDF2

Building is currently only tested on Arch Linux, Ubuntu, and MacOS. Windows builds require MinGW.

### 1) Install dependencies

<details>
  <summary>Arch Linux Dependencies</summary>

```
# All
pacman -S cmake base-devel make python python-pip bison imagemagick gtk3
pip3 install cogapp

# Win32/MinGW
pacman -S mingw-w64

# Linux 32-bit
pacman -S multilib-devel lib32-sdl2 lib32-sdl2_mixer lib32-glew lib32-openal

# Linux 64-bit
pacman -S clang sdl2 sdl2_mixer glew openal

# WebAssembly
pacaur -S emscripten
```
</details>

<details>
  <summary>Ubuntu Dependencies</summary>

```
# All
apt install build-essential cmake make python3 python3-pip bison imagemagick libgtk-3-dev
pip3 install cogapp

# Win32/MinGW
apt install mingw-w64

# Linux 32-bit
# TODO find equivalents: multilib-devel lib32-sdl2 lib32-glew lib32-openal

# Linux 64-bit
apt install clang libsdl2-dev libsdl2-mixer-dev libopenal-dev libglew-dev

# WebAssembly
# TODO find equivalents: emscripten
```

Add the following to the end of ~/.bashrc:
```
export PATH=$PATH:~/.local/bin
```
</details>

<details>
  <summary>MacOS Dependencies</summary>

Before starting, install Xcode. This is required for OpenGL headers, among other things.
```
# All
brew install cmake make python3 imagemagick
pip3 install cogapp generate-iconset

# After installing cogapp, make sure the following is in your ~/.zshrc:
# export PATH=$PATH:$HOME/Library/Python/3.8/bin

# Win32/MinGW building
brew install mingw-w64

# MacOS 64-bit
brew install openal-soft sdl2 sdl2_mixer glew

# WebAssembly
brew install emscripten
```
</details>

### 2) Compile the desired target

<details>
  <summary>64-bit Linux/SDL2</summary>

64-bit Linux supports both x86_64 and ARM64 targets, and has been tested on Intel, NVIDIA and V3D (Raspberry Pi 4) graphics cards.

```
mkdir -p build
cd build

cmake ..
make -j10
```
</details>

<details>
  <summary>64-bit Windows/SDL2, using MinGW</summary>

64-bit Windows can be cross-compiled from Linux or MacOS, and has been tested on Intel and NVIDIA graphics cards.

```
./build_win64.sh
```
</details>

<details>
  <summary>MacOS SDL2</summary>

A full, universal MacOS appbundle can be created using
```
./distpkg_macos.sh
```

Otherwise, a plain binary and single-architecture appbundle can be compiled using:
```
mkdir -p build_darwin64
cd build_darwin64

cmake ..
make -j10
codesign -s - openjkdf2-64
```
</details>

<details>
  <summary>Emscripten/WebAssembly</summary>

WASM builds are semi-supported, but break often. The last tested tag for WASM is `v0.2.0`.

```
mkdir -p wasm_out
```

Copy your `episode/` and `resource/` directory to `wasm_out`, then

```
rm -rf build_emcc
mkdir -p build_emcc
cd build_emcc
cmake .. --toolchain ../cmake_modules/wasm_toolchain.cmake
make -j10
```
</details>

<details>
  <summary>x86 Linux/SDL2, mmap blobs</summary>

OpenJKDF2 supports an experimental hybrid compilation for Linux/SDL2 which uses `JK.EXE` for any unimplemented functions. Compile using: 

```
mkdir -p build_blobs
cd build_blobs

cmake .. -DOPENJKDF2_USE_BLOBS=true
make -j10
``` 

then copy `openjkdf2` to the same directory as JK.EXE and run it. *JK.EXE version 1.0.0 is required in order to use blobs!*

`mmap` is used to maintain all `.rodata`, `.data`, and `.bss` variables in the same addresses as `JK.EXE`, and if `openjkdf2` invokes an unimplemented function, it will jump to the mapped `JK.EXE` implementation.
</details>

<details>
  <summary>32-bit Linux/SDL2, blobless</summary>

```
mkdir -p build
cd build

cmake .. --toolchain ../cmake_modules/linux_32_toolchain.cmake
make -j10
```
</details>

<details>
  <summary>x86 Win32/MinGW hook DLL</summary>

`./build.sh`
</details>