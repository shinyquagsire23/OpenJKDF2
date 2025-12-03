#!/bin/bash

rm -rf build_nintendo_dsi
rm -rf nintendo-dsi-package

./build_twl_podman.sh
if [ $? -ne 0 ]; then
    exit -1
fi

rm -f nintendo-dsi-debug.zip
rm -f nintendo-dsi-shareware-demo.zip

cp -r packaging/dsi/sdcard nintendo-dsi-package
cp build_nintendo_dsi/openjkdf2.nds nintendo-dsi-package/openjkdf2.nds

rm -f nintendo-dsi-package/.dummy
dot_clean -vm nintendo-dsi-package
find nintendo-dsi-package -name .DS_Store -type f -delete # did they fkn break dot_clean fml

# Zip number 1, just the smol assets and binary
cd nintendo-dsi-package ; zip -r ../nintendo-dsi-debug.zip . ; cd ..

dot_clean -vm nintendo-dsi-package
find nintendo-dsi-package -name .DS_Store -type f -delete
cp -r wasm_out/jk1/* nintendo-dsi-package/jk1
cp -r wasm_out/mots/* nintendo-dsi-package/mots

rm -f nintendo-dsi-package/jk1/*.json
rm -f nintendo-dsi-package/mots/*.json
rm -rf nintendo-dsi-package/jk1/resource/video
rm -rf nintendo-dsi-package/mots/resource/video
rm -rf nintendo-dsi-package/jk1/player_
rm -rf nintendo-dsi-package/mots/player_
rm -rf nintendo-dsi-package/jk1/player
rm -rf nintendo-dsi-package/mots/player

# zip number 2, shareware assets included
cd nintendo-dsi-package ; zip -r ../nintendo-dsi-shareware-demo.zip . ; cd ..

rm -rf build_nintendo_dsi
rm -rf nintendo-dsi-package