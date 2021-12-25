import sys
from pathlib import Path
import os
import struct

if (len(sys.argv) < 2):
    print("Usage: gob-extract.py <filename.gob>\n")
    print("Assets are extracted to <filename>/")
    exit(-1)

p = Path(sys.argv[1])
extract_dir = str(p.parent) + "/" + p.name.split(".")[0]

os.makedirs(extract_dir, exist_ok=True)

f = open(sys.argv[1], "rb")

magic, version, entrytable_offs = struct.unpack("<LLL", f.read(12))

f.seek(entrytable_offs)

num_files, = struct.unpack("<L", f.read(4))

for i in range(0, num_files-1):
    f.seek(entrytable_offs + 4 + (i * (128+8)))
    print (hex(entrytable_offs + 4 + (i * (128+8))))

    f_offs, f_size, f_name = struct.unpack("<LL128s", f.read(128+8))
    print (f_name)
    f_name = f_name.split(b"\x00")[0].decode("utf-8").replace("\\", "/")
    
    print (f_offs, f_size, f_name)
    
    full_path = extract_dir + "/" + f_name
    p_f = Path(full_path)
    os.makedirs(str(p_f.parent), exist_ok=True)
    
    f_out = open(full_path, "wb")
    f.seek(f_offs)
    contents = f.read(f_size)
    if contents[-1] == 0x1a:
        contents = contents[:-1]
    f_out.write(contents)
    f_out.close()

f.close()
print (magic, version, entrytable_offs, num_files)
