#!/bin/zsh

rm -rf win64-package
make -f Makefile.win64 clean
make -f Makefile.win64 -j10

cp -r resource win64-package
rm -f win64-debug.zip
cd win64-package ; zip -r ../win64-debug.zip . ; cd ..

make -f Makefile.win64 clean
rm -rf win64-package