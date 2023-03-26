#!/bin/bash
base="$1"
outdir="$2"

mkdir -p "$outdir"

for length in 16 32 64 128 256 512 24 48 96 192 384
    do blur=$(bc <<< "scale=9; 1 / $length")
    convert "$base" -filter Box -define filter:blur="$blur" -dither None -resize "${length}x$length" -type PaletteMatte -interlace None "$outdir/$length.png"
done
