#!/bin/bash
find ./build_switch_simple -name '*.o' | grep sith_engine.dir > all_o_files.txt

while read -r obj; do
  if /opt/devkitpro/devkitA64/bin/aarch64-none-elf-readelf -SW "$obj" | grep -q '.init_array'; then
    echo ">>> $obj"
    /opt/devkitpro/devkitA64/bin/aarch64-none-elf-objdump -s -j .init_array "$obj" | grep -v '0000000008' && echo "⚠️ Suspicious"
    echo
  fi
done < all_o_files.txt
