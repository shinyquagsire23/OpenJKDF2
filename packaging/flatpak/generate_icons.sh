#!/bin/bash
base=$1
outdir=$2

mkdir -p $outdir

convert "$base" -resize '16x16'     -unsharp 1x4 "$outdir/16.png"
convert "$base" -resize '32x32'     -unsharp 1x4 "$outdir/32.png"
convert "$base" -resize '48x48'     -unsharp 1x4 "$outdir/48.png"
convert "$base" -resize '64x64'     -unsharp 1x4 "$outdir/64.png"
convert "$base" -resize '128x128'   -unsharp 1x4 "$outdir/128.png"
convert "$base" -resize '256x256'   -unsharp 1x4 "$outdir/256.png"
convert "$base" -resize '512x512'   -unsharp 1x4 "$outdir/512.png"
