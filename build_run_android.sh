#!/bin/bash

./build_android.sh && adb shell am start -n org.openjkdf2.app/.GameActivity

#adb push wasm_out/jk1 /storage/self/primary/Android/data/org.openjkdf2.app/files/
#adb push wasm_out/mots /storage/self/primary/Android/data/org.openjkdf2.app/files/
