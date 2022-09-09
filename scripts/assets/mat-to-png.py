import png
import struct
import sys
from pathlib import Path

f_path = sys.argv[1]
p = Path(sys.argv[1])

colormap_lut = {}
colormap_lut["00"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/uicolormap.cmp"
colormap_lut["01"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/01narsh.cmp"
colormap_lut["01"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/01narsh.cmp"
colormap_lut["03"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/03house.cmp"
colormap_lut["04"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/04farm.cmp"
colormap_lut["06"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/06baron.cmp"
colormap_lut["09"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/09fuel.cmp"
colormap_lut["10"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/10cargo.cmp"
colormap_lut["11"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/11pic.cmp"
colormap_lut["12"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/12escape.cmp"
colormap_lut["13"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/12escape.cmp"
colormap_lut["14"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/15maw.cmp"
colormap_lut["15"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/15maw.cmp"
colormap_lut["16"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/16fall.cmp"
colormap_lut["17"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/17sarris.cmp"
colormap_lut["19"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/19descent.cmp"
colormap_lut["20"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/20val.cmp"
colormap_lut["21"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/20val.cmp"
colormap_lut["m4"] = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/m4escape.cmp"

colormap_fname = "/home/maxamillion/workspace/OpenJKDF2/DF2/resource/Res2/misc/cmp/uicolormap.cmp"
if p.name[:2] in colormap_lut:
    colormap_fname = colormap_lut[p.name[:2]]

f_pal = open(colormap_fname, "rb")
f_pal.seek(0x40)
f_pal_raw = f_pal.read(0x300);
f_pal.close()

def get_pal_color(n):
    return (f_pal_raw[(n*3)], f_pal_raw[(n*3)+1], f_pal_raw[(n*3)+2])

with open(f_path, "rb") as f:
    # BM file
    #magic, idk1, idk2, palFmt, numMips, xPos, yPos, colorkey = struct.unpack("<LLLLLLLL", f.read(8*4))
    #is16bit, bpp, r_bits, g_bits, b_bits, r_shift, g_shift, b_shift, r_bitdiff, g_bitdiff, b_bitdiff, unk_40, unk_44, unk_48 = struct.unpack("<LLLLLLLLLLLLLL", f.read(14*4))

    magic, revision, _type, num_texinfo, num_textures = struct.unpack("<LLLLL", f.read(5*4))
    is16bit, bpp, r_bits, g_bits, b_bits, r_shift, g_shift, b_shift, r_bitdiff, g_bitdiff, b_bitdiff, unk_40, unk_44, unk_48 = struct.unpack("<LLLLLLLLLLLLLL", f.read(14*4))

    texinfos = {}
    textures = {}

    for i in range(0, num_texinfo):
        texture_type, b, c, d, e, _f = struct.unpack("<LLLLLL", f.read(6*4))
        if (texture_type & 8) != 0:
            ext_a, height, alpha_en, ext_d = struct.unpack("<LLLL", f.read(4*4))

        texinfos[i] = {}

    for i in range(0, num_textures):
        width, height, alpha_en, unk_0c, unk_10, num_mipmaps = struct.unpack("<LLLLLL", f.read(6*4))
        textures[i] = {}
        textures[i]["width"] = width
        textures[i]["height"] = height
        textures[i]["alpha_en"] = alpha_en
        textures[i]["num_mipmaps"] = num_mipmaps
        data = f.read(width * height)
        
        img = []
        for y in range(height):
            row = ()
            for x in range(width):
                val = data[(y*width) + x]
                row = row + get_pal_color(val)
            img.append(row)
        with open(f_path.replace(".mat", "") + "_" + str(i) + ".png", 'wb') as f_out:
            w = png.Writer(width, height, greyscale=False)
            w.write(f_out, img)

#for i in range(0, num_textures):
#    print (textures[i])
