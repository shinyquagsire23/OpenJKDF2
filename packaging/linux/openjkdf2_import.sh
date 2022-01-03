#! /bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <gog_installer>"
    exit
fi
gameid=$(innoextract -s --gog-game-id -- "$1")
if [ "$gameid" != 1422286819 ]; then
    echo "Specified file is not a JK:DF2 GOG installer" >&2
    exit 1;
fi
tmpdir=$(mktemp -d)
innoextract -q -d "$tmpdir" -I app/Resource -I app/MUSIC -I app/Episode -I app/player -I app/JK.EXE -- "$1"
mv "$tmpdir/app/Resource"           "$tmpdir/app/resource"
mv "$tmpdir/app/resource/VIDEO"     "$tmpdir/app/resource/video"
mv "$tmpdir/app/resource/JK_.CD"    "$tmpdir/app/resource/jk_.cd"
mv "$tmpdir/app/Episode"            "$tmpdir/app/episode"
mv "$tmpdir/app/episode/JK1.GOB"    "$tmpdir/app/episode/JK1.gob"
mv "$tmpdir/app/episode/JK1CTF.GOB" "$tmpdir/app/episode/JK1CTF.gob"
mv "$tmpdir/app/episode/JK1MP.GOB"  "$tmpdir/app/episode/JK1MP.gob"
sudo mkdir -p /usr/share/openjkdf2
sudo cp -r "$tmpdir/app/"* /usr/share/openjkdf2
rm -rf "$tmpdir"