#!/bin/bash
base="$1"

for length in 16 24 32 48 64 96 128 192 256 384 512
    do install -pDm 0644 "$base/$length.png" "$FLATPAK_DEST/share/icons/hicolor/${length}x$length/apps/org.openjkdf2.OpenJKDF2.png"
done
