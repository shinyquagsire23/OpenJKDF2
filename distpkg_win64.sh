#!/bin/zsh

rm -rf win64-package
rm -f win64-debug.zip

rm -rf build_win64
mkdir -p build_win64 && cd build_win64
cmake .. --toolchain ../cmake_modules/mingw_toolchain.cmake &&
make -j10 &&
cd .. &&

mkdir -p win64-package
cp build_win64/*.dll win64-package
cp build_win64/*.exe win64-package

#make -f Makefile.win64 clean
#make -f Makefile.win64 -j10

#cp -r resource win64-package
rm -f win64-debug.zip
cd win64-package ; zip -r ../win64-debug.zip . ; cd ..

#make -f Makefile.win64 clean
rm -rf build_win64
rm -rf win64-package