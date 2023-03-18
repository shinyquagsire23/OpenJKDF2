#!/bin/sh

# Run in OpenJKDF2 directory:
# python -m SimpleHTTPServer

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

mkdir -p wasm_out
mkdir -p wasm_out/jk1
mkdir -p wasm_out/mots

rm -f wasm_out/openjkdf2.js
rm -f wasm_out/openjkdf2.wasm
rm -f wasm_out/openjkdf2.data
rm -rf wasm_out/jk1/resource/shaders
mkdir -p wasm_out/jk1/resource/shaders
rm -rf wasm_out/mots/resource/shaders
mkdir -p wasm_out/mots/resource/shaders
cp resource/shaders/* wasm_out/jk1/resource/shaders
cp resource/shaders/* wasm_out/mots/resource/shaders

#rm -rf build_emcc
mkdir -p build_emcc && cd build_emcc
cmake .. --toolchain ../cmake_modules/toolchain_wasm.cmake
cmake .. --toolchain ../cmake_modules/toolchain_wasm.cmake
make -j10 VERBOSE=1
cd ..

cp build_emcc/openjkdf2.js wasm_out/openjkdf2.js
cp build_emcc/openjkdf2.wasm wasm_out/openjkdf2.wasm
cp build_emcc/openjkdf2.data wasm_out/openjkdf2.data

gsed -i 's/var hasByteServing/var hasByteServing = false;\/\//g' wasm_out/openjkdf2.js

# Update maxthomas.dev/openjkdf2, if you're me
whodis=$(whoami)
if [ "$whodis"  = 'maxamillion' ]; then
    cp wasm_out/openjkdf2.wasm ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/index.html ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/openjkdf2.data ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/openjkdf2.js ../shinyquagsire23.github.io/openjkdf2
fi