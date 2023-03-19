#!/bin/bash
base=../icon.png
outdir=app/src/main/res

mkdir -p $outdir

convert "$base" -resize '48x48'     -unsharp 1x4 "$outdir/mipmap-mdpi/ic_launcher.png"
convert "$base" -resize '72x72'     -unsharp 1x4 "$outdir/mipmap-hdpi/ic_launcher.png"
convert "$base" -resize '96x96'     -unsharp 1x4 "$outdir/mipmap-xhdpi/ic_launcher.png"
convert "$base" -resize '144x144'     -unsharp 1x4 "$outdir/mipmap-xxhdpi/ic_launcher.png"
convert "$base" -resize '192x192'   -unsharp 1x4 "$outdir/mipmap-xxxhdpi/ic_launcher.png"
