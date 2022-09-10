#!/bin/zsh
rm -rf build_linux64_flatpak
rm -rf build_linux64

bash packaging/flatpak/generate_icons.sh packaging/icon.png packaging/flatpak/icons

flatpak-builder --user --install --force-clean build_linux64_flatpak org.openjkdf2.OpenJKDF2.yml
flatpak install openjkdf2-origin org.openjkdf2.OpenJKDF2.Debug
#flatpak run org.openjkdf2.OpenJKDF2
#flatpak run --command=sh --devel org.openjkdf2.OpenJKDF2
