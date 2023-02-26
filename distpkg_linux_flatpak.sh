#!/bin/sh

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

#rm -rf build_linux_arm64_flatpak
#rm -rf build_linux_x86_64_flatpak
rm -rf build_linux

# There's no caching for dir type sources
commit=$(git log -n 1 --pretty=format:"%H")
sed "s/REPLACE_COMMIT_HASH/$commit/g" packaging/flatpak/org.openjkdf2.OpenJKDF2.template.yml > org.openjkdf2.OpenJKDF2.yml

# Only needed if icon actually changes
#bash packaging/flatpak/generate_icons.sh packaging/icon.png packaging/flatpak/icons

# It's *my* sleepover and *I* get to choose the dominant architecture
flatpak-builder --user --repo=flatpak_openjkdf2 --force-clean --arch=aarch64 build_linux_arm64_flatpak org.openjkdf2.OpenJKDF2.yml
flatpak-builder --user --repo=flatpak_openjkdf2 --force-clean --arch=x86_64 build_linux_x86_64_flatpak org.openjkdf2.OpenJKDF2.yml

flatpak build-bundle flatpak_openjkdf2 OpenJKDF2.flatpak org.openjkdf2.OpenJKDF2

# Commands I forget frequently enough to keep notes here
#flatpak install openjkdf2 org.openjkdf2.OpenJKDF2
#flatpak install openjkdf2 org.openjkdf2.OpenJKDF2.Debug
#flatpak run org.openjkdf2.OpenJKDF2
#flatpak run --command=sh --devel org.openjkdf2.OpenJKDF2

# Cleanup
#rm -rf build_linux_arm64_flatpak
#rm -rf build_linux_x86_64_flatpak
#rm -rf flatpak_openjkdf2
