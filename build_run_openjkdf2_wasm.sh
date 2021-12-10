#!/bin/zsh

# Run in OpenJKDF2 directory:
# python -m SimpleHTTPServer

make -f Makefile.emcc clean

cp resource/* wasm_out/resource/

make -f Makefile.emcc -j10

gsed -i 's/var hasByteServing/var hasByteServing = false;\/\//g' wasm_out/openjkdf2.js

# Update maxthomas.dev/openjkdf2, if you're me
whodis=$(whoami)
if [ "$whodis"  = 'maxamillion' ]; then
    cp wasm_out/openjkdf2.wasm ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/index.html ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/openjkdf2.data ../shinyquagsire23.github.io/openjkdf2
    cp wasm_out/openjkdf2.js ../shinyquagsire23.github.io/openjkdf2
fi