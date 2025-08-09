#!/bin/bash

# Paths to devkitPro toolchain tools
READELF="/opt/devkitpro/devkitA64/bin/aarch64-none-elf-readelf"
OBJDUMP="/opt/devkitpro/devkitA64/bin/aarch64-none-elf-objdump"

# Find all object files in sith_engine object library
find ./build_switch_simple -type f -name "*.o" | > all_engine_objects.txt

echo "Scanning for .init_array sections..."
echo

while read -r obj; do
  if $READELF -SW "$obj" | grep -q '.init_array'; then
    echo ">>> $obj"
    $OBJDUMP -s -j .init_array "$obj"

    # Optional: detect clearly bad entries (very low addresses)
    echo "Checking for suspicious values:"
    $OBJDUMP -s -j .init_array "$obj" | grep -E '00000000[0-9a-f]{4}' | grep -v '0000000008' && echo "⚠️ Suspicious init_array entries detected!"

    echo
  fi
done < all_engine_objects.txt
