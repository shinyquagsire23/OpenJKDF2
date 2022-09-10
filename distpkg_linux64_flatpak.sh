#!/bin/zsh
rm -rf build_linux_arm64_flatpak
rm -rf build_linux_x86_64_flatpak
rm -rf build_linux64

bash packaging/flatpak/generate_icons.sh packaging/icon.png packaging/flatpak/icons

flatpak-builder --user --repo=openjkdf2 --force-clean --arch=aarch64 build_linux_arm64_flatpak org.openjkdf2.OpenJKDF2.yml
flatpak-builder --user --repo=openjkdf2 --force-clean --arch=x86_64 build_linux_x86_64_flatpak org.openjkdf2.OpenJKDF2.yml
flatpak install openjkdf2 org.openjkdf2.OpenJKDF2
flatpak install openjkdf2 org.openjkdf2.OpenJKDF2.Debug
#flatpak run org.openjkdf2.OpenJKDF2
#flatpak run --command=sh --devel org.openjkdf2.OpenJKDF2
