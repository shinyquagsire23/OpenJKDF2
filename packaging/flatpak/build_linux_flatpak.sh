#!/bin/bash

git submodule update --init

mkdir -p build_linux && pushd build_linux

cmake -DCMAKE_INSTALL_PREFIX=$FLATPAK_DEST .. &&
(make -j $(nproc) PROTOBUF || make -j1 PROTOBUF) && 
make -j $(nproc) openjkdf2 &&
popd &&
mkdir -p $FLATPAK_DEST/share/applications/ &&
mkdir -p $FLATPAK_DEST/bin &&
mkdir -p $FLATPAK_DEST/share/metainfo &&
install -Dp -m 0555 -o 0 -g 0 build_linux/openjkdf2 $FLATPAK_DEST/bin &&
install -Dp -m 0555 -o 0 -g 0 build_linux/*.so $FLATPAK_DEST/lib &&
install -Dp -m 0444 -o 0 -g 0 packaging/flatpak/org.openjkdf2.OpenJKDF2.desktop $FLATPAK_DEST/share/applications &&
install -Dp -m 0444 -o 0 -g 0 LICENSE.md $FLATPAK_DEST/share/licenses/openjkdf2 &&
install -Dp -m 0444 -o 0 -g 0 README.md $FLATPAK_DEST/share/doc/openjkdf2 &&
install -Dp -m 0444 -o 0 -g 0 packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml $FLATPAK_DEST/share/metainfo &&
bash packaging/flatpak/copy_icons.sh packaging/flatpak/icons
