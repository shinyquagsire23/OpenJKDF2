import sys
from pathlib import Path
import os
import struct

# Counterpart to gob-extract.py: packs a directory into a GOB container.
#
# Layout matches retail GOBs (and what stdGob.c expects):
#   +0  char[4]  "GOB "
#   +4  u32      version (20)
#   +8  u32      entrytable_offs
#   at entrytable_offs:
#       u32      num_files
#       entries: { u32 offset; u32 size; char name[128]; } * num_files
#   file data follows the entry table.
#
# Entry names use backslash separators, relative to the packed directory.

if (len(sys.argv) < 2):
    print("Usage: gob-pack.py <directory> [output.gob]\n")
    print("Packs <directory>/ into <directory>.gob (or output.gob if given).")
    print("Note: the engine matches entry names as-is; JK assets are")
    print("conventionally lowercase (use --lower to force-lowercase names).")
    exit(-1)

force_lower = "--lower" in sys.argv
args = [a for a in sys.argv[1:] if a != "--lower"]

src_dir = Path(args[0])
if not src_dir.is_dir():
    print("Not a directory: %s" % src_dir)
    exit(-1)

out_path = args[1] if len(args) > 1 else str(src_dir.parent / (src_dir.name + ".gob"))

# Collect files, sorted for deterministic output
files = []
for root, dirs, names in os.walk(src_dir):
    dirs.sort()
    for name in sorted(names):
        full = Path(root) / name
        rel = full.relative_to(src_dir)
        entry_name = str(rel).replace("/", "\\")
        if force_lower:
            entry_name = entry_name.lower()
        encoded = entry_name.encode("latin-1")
        if len(encoded) > 127:
            print("Entry name too long (>127): %s" % entry_name)
            exit(-1)
        files.append((entry_name, encoded, full, full.stat().st_size))

if not files:
    print("No files found in %s" % src_dir)
    exit(-1)

entrytable_offs = 12
data_offs = entrytable_offs + 4 + len(files) * (128 + 8)

f = open(out_path, "wb")
f.write(struct.pack("<4sLL", b"GOB ", 20, entrytable_offs))
f.write(struct.pack("<L", len(files)))

# Entry table
offs = data_offs
entry_offsets = []
for entry_name, encoded, full, size in files:
    f.write(struct.pack("<LL128s", offs, size, encoded))
    entry_offsets.append(offs)
    offs += size

# File data
for (entry_name, encoded, full, size), e_offs in zip(files, entry_offsets):
    with open(full, "rb") as f_in:
        f.write(f_in.read())
    print("%08x %8d %s" % (e_offs, size, entry_name))

f.close()
print("Packed %d files (%d bytes) -> %s" % (len(files), offs, out_path))
