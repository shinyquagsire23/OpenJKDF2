#!/bin/zsh
#rm -rf build_linux_arm64_flatpak
#rm -rf build_linux_x86_64_flatpak
rm -rf build_linux64

commit=$(git log -n 1 --pretty=format:"%H")

sed "s/REPLACE_COMMIT_HASH/$commit/g" packaging/flatpak/org.openjkdf2.OpenJKDF2.template.yml > org.openjkdf2.OpenJKDF2.yml

#bash packaging/flatpak/generate_icons.sh packaging/icon.png packaging/flatpak/icons

flatpak-builder --user --repo=flatpak_openjkdf2 --force-clean --arch=aarch64 build_linux_arm64_flatpak org.openjkdf2.OpenJKDF2.yml
#flatpak-builder --user --repo=flatpak_openjkdf2 --force-clean --arch=x86_64 build_linux_x86_64_flatpak org.openjkdf2.OpenJKDF2.yml

flatpak build-bundle flatpak_openjkdf2 OpenJKDF2.flatpak org.openjkdf2.OpenJKDF2

#flatpak install openjkdf2 org.openjkdf2.OpenJKDF2
#flatpak install openjkdf2 org.openjkdf2.OpenJKDF2.Debug
#flatpak run org.openjkdf2.OpenJKDF2
#flatpak run --command=sh --devel org.openjkdf2.OpenJKDF2
