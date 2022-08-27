#!/bin/zsh

# Run in OpenJKDF2 directory:
# python -m SimpleHTTPServer

#cp resource/* wasm_out/resource/

rm -rf build_emcc
mkdir -p build_emcc && cd build_emcc
cmake .. --toolchain ../cmake_modules/wasm_toolchain.cmake && make -j10 VERBOSE=1
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