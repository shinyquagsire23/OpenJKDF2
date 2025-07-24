import png # pip3 install pypng
import struct
import sys
import glob
import os
import math
from pathlib import Path

dir_path = Path(sys.argv[1])

search_dirs = \
[
#"dwMin/parts/mat",
#"dwHD/parts/mat",
"dwCD/mission/mat",
"dwCD/mission/3do/mat",
]

blacklisted = [
"dwCD/mission/mat/00t_2.mat",
"dwCD/mission/mat/00t_3.mat",
"dwCD/mission/mat/00t_4.mat",
"dwCD/mission/mat/00t_5.mat",
"dwCD/mission/mat/00t_6.mat",
"dwCD/mission/mat/00t_7.mat",
"dwCD/mission/mat/00t_8.mat",
"dwCD/mission/mat/dp_blt1.mat",
"dwCD/mission/mat/dp_door.mat",
"dwCD/mission/mat/dp_elevator.mat",
"dwCD/mission/mat/dp_flatpanel.mat",
"dwCD/mission/mat/dp_floor.mat",
"dwCD/mission/mat/dp_octtop.mat",
"dwCD/mission/mat/dp_panel_side.mat",
"dwCD/mission/mat/dp_pipe.mat",
"dwCD/mission/mat/dp_ra01.mat",
"dwCD/mission/mat/dp_ra03.mat",
"dwCD/mission/mat/dp_roof.mat",
"dwCD/mission/mat/dp_sa01.mat",
"dwCD/mission/mat/dp_upperpanel.mat",
"dwCD/mission/mat/dp_upperpanel2.mat",
"dwCD/mission/mat/numbers.mat",
"dwCD/mission/mat/roadblk.mat",
"dwCD/mission/mat/roadsign.mat",

"dwCD/mission/3do/mat/mx4arm.mat",
"dwCD/mission/3do/mat/mxarm.mat",
"dwCD/mission/3do/mat/mxbelly.mat",
"dwCD/mission/3do/mat/mxchest.mat",
"dwCD/mission/3do/mat/mxear.mat",
"dwCD/mission/3do/mat/mxfoot.mat",
"dwCD/mission/3do/mat/mxhand.mat",
"dwCD/mission/3do/mat/mxhandi.mat",
"dwCD/mission/3do/mat/mxhead.mat",
"dwCD/mission/3do/mat/mxheadb.mat",
"dwCD/mission/3do/mat/mxleg.mat",
"dwCD/mission/3do/mat/mxthigh.mat",
]

'''
mat_list = []
for d in search_dirs:
    mat_list += glob.glob(str(dir_path / Path(d) / "*.mat"))
#print (mat_list)

for b in blacklisted:
    mat_list.remove(str(dir_path / Path(b)))

jkl_list = glob.glob(str(dir_path / "dwCD/mission/*.jkl"))

jkl_gen = jkl_list[0]

def get_jkl_mats(jkl_fpath):
    mats = []
    with open(jkl_fpath, "r") as f:
        lines = f.read().split("\n")
        read_mats = False
        for i in range(0, len(lines)):
            l = lines[i]
            if "World materials" in l:
                read_mats = True
                continue
            if l == "end":
                read_mats = False

            if not read_mats:
                continue

            if len(l) < 1 or l[0] == '#':
                continue
            mats += [l.split("\t")[1]]
        
    return mats

mat_list_partial = get_jkl_mats(jkl_gen)
mat_list_real = []
for m in mat_list:
    if Path(m).name in mat_list_partial:
        mat_list_real += [m]

#mat_list = mat_list_real
'''

basepath = "/Users/maxamillion/workspace/OpenJKDF2/DF2_res/Res2/"
basepath_dw = "/Users/maxamillion/workspace/OpenJKDF2/DW_res/dwCD/"

colormap_lut = {}
colormap_lut["00"] = basepath + "misc/cmp/uicolormap.cmp"
colormap_lut["01"] = basepath + "misc/cmp/01narsh.cmp"
colormap_lut["01"] = basepath + "misc/cmp/01narsh.cmp"
colormap_lut["03"] = basepath + "misc/cmp/03house.cmp"
colormap_lut["04"] = basepath + "misc/cmp/04farm.cmp"
colormap_lut["06"] = basepath + "misc/cmp/06baron.cmp"
colormap_lut["09"] = basepath + "misc/cmp/09fuel.cmp"
colormap_lut["10"] = basepath + "misc/cmp/10cargo.cmp"
colormap_lut["11"] = basepath + "misc/cmp/11pic.cmp"
colormap_lut["12"] = basepath + "misc/cmp/12escape.cmp"
colormap_lut["13"] = basepath + "misc/cmp/12escape.cmp"
colormap_lut["14"] = basepath + "misc/cmp/15maw.cmp"
colormap_lut["15"] = basepath + "misc/cmp/15maw.cmp"
colormap_lut["16"] = basepath + "misc/cmp/16fall.cmp"
colormap_lut["17"] = basepath + "misc/cmp/17sarris.cmp"
colormap_lut["19"] = basepath + "misc/cmp/19descent.cmp"
colormap_lut["20"] = basepath + "misc/cmp/20val.cmp"
colormap_lut["21"] = basepath + "misc/cmp/20val.cmp"
colormap_lut["m4"] = basepath + "misc/cmp/m4escape.cmp"
colormap_lut["ui"] = basepath + "misc/cmp/uicolormap.cmp"

colormap_lut["dw_reference"] = basepath_dw + "misc/reference.cmp"
colormap_lut["dw_workshop"] = basepath_dw + "misc/workshop.cmp"
colormap_lut["dw_deploy"] = basepath_dw + "misc/deploy.cmp"
colormap_lut["dw_mission"] = basepath_dw + "misc/mission.cmp"
colormap_lut["dw_workshop2"] = basepath_dw + "misc/workshop2.cmp"
colormap_lut["dw_textures"] = basepath_dw + "misc/textures.cmp"
colormap_lut["dw_ending"] = basepath_dw + "misc/ending.cmp"
colormap_lut["dw_options"] = basepath_dw + "misc/options.cmp"
colormap_lut["dw_opening"] = basepath_dw + "misc/opening.cmp"
colormap_lut["dw_status"] = basepath_dw + "misc/status.cmp"


class CmpPal:
    def __init__(self, f_path):
        f_pal = open(f_path, "rb")
        self.header = f_pal.read(0x40)
        self.pal_raw = list(f_pal.read(0x300))
        self.lightlevel = list(f_pal.read(0x4000))
        self.transparency = []
        for i in range(0, 256):
            self.transparency += [list(f_pal.read(0x100))]
        f_pal.close()

    def write(self, f_path):
        with open(f_path, "wb") as f:
            f.write(self.header)
            f.write(bytes(self.pal_raw))
            f.write(bytes(self.lightlevel))
            for i in range(0, 256):
                f.write(bytes(self.transparency[i]))

    def get_color(self, n):
        return (self.pal_raw[(n*3)], self.pal_raw[(n*3)+1], self.pal_raw[(n*3)+2])

    def set_color(self, n, c):
        self.pal_raw[(n*3)] = c[0]
        self.pal_raw[(n*3)+1] = c[1]
        self.pal_raw[(n*3)+2] = c[2]

    def get_lightlevels(self, n):
        out = []
        for i in range(0, 0x40):
            out += [self.lightlevel[(0x100 * i) + n]]
        return out

    def set_lightlevels(self, n, levels):
        for i in range(0, 0x40):
            self.lightlevel[(0x100 * i) + n] = levels[i]

    def get_transparency(self, n):
        return self.transparency[n]

    def set_transparency(self, n, val):
        self.transparency[n] = val

    def is_emissive(self, n):
        vals = self.get_lightlevels(n)
        x = vals[0]
        for v in vals:
            if x != v:
                return False
        return True

    def closest_color(self, other_cmp, n, check_emissive=True):
        needs_emissive = self.is_emissive(n)
        rgb = self.get_color(n)
        r, g, b = rgb
        color_diffs = []
        for i in range(1, 256):
            if check_emissive and needs_emissive and not other_cmp.is_emissive(i):
                continue
            color = other_cmp.get_color(i)
            cr, cg, cb = color
            color_diff = math.sqrt((r - cr)**2 + (g - cg)**2 + (b - cb)**2)
            color_diffs.append((color_diff, i))
        return min(color_diffs)[1]

    def find_matching_color(self, other_cmp, n):
        if n == 0:
            return 0

        for i in range(1, 256):
            if self.get_color(n) == other_cmp.get_color(i):
                return i

        return -1

    def write_png(self, fpath):
        width = 16
        height = 16
        idx = 0
        img = []
        for y in range(height):
            row = ()
            for x in range(width):
                val = idx#data[(y*width) + x]
                row = row + self.get_color(val)
                idx += 1
            img.append(row)

        with open(fpath, 'wb') as f_out:
            w = png.Writer(16, 16, greyscale=False)
            w.write(f_out, img)

# Write out PNGs for all the CMPs
def write_cmp_pngs():
    global colormap_lut

    out_dir = str(dir_path / "png_conv") + "/"

    for k in colormap_lut:
        path = colormap_lut[k]
        f = open(path, "rb")
        f.seek(0x40)
        pal_raw = f.read(0x300);

        def _get_pal_color(n):
            return (pal_raw[(n*3)], pal_raw[(n*3)+1], pal_raw[(n*3)+2])

        width = 16
        height = 16
        idx = 0
        img = []
        for y in range(height):
            row = ()
            for x in range(width):
                val = idx#data[(y*width) + x]
                row = row + _get_pal_color(val)
                idx += 1
            img.append(row)

        with open(out_dir + k + ".png", 'wb') as f_out:
            w = png.Writer(16, 16, greyscale=False)
            w.write(f_out, img)

        f.close()

def mat_to_png(f_path, cmp_name=None):
    global colormap_lut

    out_dir = str(dir_path / "png_conv") + "/"
    os.makedirs(out_dir, exist_ok=True)

    os.makedirs(out_dir + "/".join(Path(f_path).parts[:-1]), exist_ok=True)

    p = Path(sys.argv[1])

    if cmp_name is not None:
        colormap_fname = colormap_lut[cmp_name]
    else:
        colormap_fname = colormap_lut["ui"]
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

            with open(out_dir + f_path.replace(".mat", "") + "_" + str(i) + ".png", 'wb') as f_out:
                w = png.Writer(width, height, greyscale=False)
                w.write(f_out, img)

not_found_list = []
def mat_to_mat(f_path, cmp_from=None, cmp_to=None):
    global colormap_lut

    out_dir = str(dir_path / "mat_conv") + "/"
    p = Path(sys.argv[1])

    def get_pal_color_from(n):
        return cmp_from.get_color(n)

    def get_pal_color_to(n):
        return cmp_to.get_color(n)

    def closest_color(n):
        return cmp_from.closest_color(cmp_to, n)

    match_lut = [-1] * 256
    for i in range(0, 256):
        match_lut[i] = cmp_from.find_matching_color(cmp_to, i)

    def find_matching_color(n):
        global not_found_list

        if n not in not_found_list:
            print("Missing match for idx", str(n))
            not_found_list += [n]

        return match_lut[n]

    #for i in range(0, 256):
    #    find_matching_color(i)

    '''
    width = 16
    height = 16
    idx = 0
    img = []
    for y in range(height):
        row = ()
        for x in range(width):
            val = idx#data[(y*width) + x]
            color = (0xFF, 0x0, 0xFF)
            if find_matching_color(val) != -1:
                color = get_pal_color_from(val)
            color = get_pal_color_to(closest_color(idx))

            row = row + color
            idx += 1
        img.append(row)

    with open(out_dir + "test.png", 'wb') as f_out:
        w = png.Writer(16, 16, greyscale=False)
        w.write(f_out, img)
    '''

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
                    row = row + get_pal_color_from(val)
                    find_matching_color(val)
                img.append(row)

            #with open(out_dir + f_path.replace(".mat", "") + "_" + str(i) + ".png", 'wb') as f_out:
            #    w = png.Writer(width, height, greyscale=False)
            #    w.write(f_out, img)

def mat_to_mat_2(f_path, cmp_from=None, cmp_to=None, close_lut=None):
    global colormap_lut

    out_dir = str(dir_path / "mat_conv") + "/"
    p = Path(sys.argv[1])

    def get_pal_color_from(n):
        return cmp_from.get_color(n)

    def get_pal_color_to(n):
        return cmp_to.get_color(n)

    def closest_color(n):
        return cmp_from.closest_color(cmp_to, n)

    match_lut = [-1] * 256
    for i in range(0, 256):
        match_lut[i] = cmp_from.find_matching_color(cmp_to, i)

    def find_matching_color(n):
        global not_found_list

        if n not in not_found_list:
            print("Missing match for idx", str(n))
            not_found_list += [n]

        return match_lut[n]

    #for i in range(0, 256):
    #    find_matching_color(i)

    '''
    width = 16
    height = 16
    idx = 0
    img = []
    for y in range(height):
        row = ()
        for x in range(width):
            val = idx#data[(y*width) + x]
            color = (0xFF, 0x0, 0xFF)
            if find_matching_color(val) != -1:
                color = get_pal_color_from(val)
            color = get_pal_color_to(closest_color(idx))

            row = row + color
            idx += 1
        img.append(row)

    with open(out_dir + "test.png", 'wb') as f_out:
        w = png.Writer(16, 16, greyscale=False)
        w.write(f_out, img)
    '''

    f_out = open(out_dir + f_path, "wb")

    with open(f_path, "rb") as f:
        # BM file
        #magic, idk1, idk2, palFmt, numMips, xPos, yPos, colorkey = struct.unpack("<LLLLLLLL", f.read(8*4))
        #is16bit, bpp, r_bits, g_bits, b_bits, r_shift, g_shift, b_shift, r_bitdiff, g_bitdiff, b_bitdiff, unk_40, unk_44, unk_48 = struct.unpack("<LLLLLLLLLLLLLL", f.read(14*4))

        magic, revision, _type, num_texinfo, num_textures = struct.unpack("<LLLLL", f.read(5*4))
        is16bit, bpp, r_bits, g_bits, b_bits, r_shift, g_shift, b_shift, r_bitdiff, g_bitdiff, b_bitdiff, unk_40, unk_44, unk_48 = struct.unpack("<LLLLLLLLLLLLLL", f.read(14*4))

        f_out.write(struct.pack("<LLLLL", magic, revision, _type, num_texinfo, num_textures))
        f_out.write(struct.pack("<LLLLLLLLLLLLLL", is16bit, bpp, r_bits, g_bits, b_bits, r_shift, g_shift, b_shift, r_bitdiff, g_bitdiff, b_bitdiff, unk_40, unk_44, unk_48))

        texinfos = {}
        textures = {}

        for i in range(0, num_texinfo):
            texture_type, b, c, d, e, _f = struct.unpack("<LLLLLL", f.read(6*4))
            
            f_out.write(struct.pack("<LLLLLL", texture_type, close_lut[b], c, d, e, _f))
            if (texture_type & 8) != 0:
                ext_a, height, alpha_en, ext_d = struct.unpack("<LLLL", f.read(4*4))
                f_out.write(struct.pack("<LLLL", ext_a, height, alpha_en, ext_d))

            texinfos[i] = {}

        for i in range(0, num_textures):
            width, height, alpha_en, unk_0c, unk_10, num_mipmaps = struct.unpack("<LLLLLL", f.read(6*4))
            f_out.write(struct.pack("<LLLLLL", width, height, alpha_en, unk_0c, unk_10, num_mipmaps))
            textures[i] = {}
            textures[i]["width"] = width
            textures[i]["height"] = height
            textures[i]["alpha_en"] = alpha_en
            textures[i]["num_mipmaps"] = num_mipmaps
            data = f.read(width * height)
            data_conv = [0] * (width * height)
            
            img = []
            for y in range(height):
                row = ()
                for x in range(width):
                    val = data[(y*width) + x]
                    color_orig = get_pal_color_from(val)
                    val_conv = close_lut[val]
                    data_conv[(y*width) + x] = val_conv
                    color = get_pal_color_to(val_conv)
                    row = row + color
                    #find_matching_color(val)
                img.append(row)

            f_out.write(bytes(data_conv))
            #with open(out_dir + f_path.replace(".mat", "") + "_" + str(i) + ".png", 'wb') as f_out:
            #    w = png.Writer(width, height, greyscale=False)
            #    w.write(f_out, img)

    f_out.close()


def convert_dw_png(f_path, cmp_dw, cmp_jk):
    print (f_path)
    #mat_to_png(f_path, "dw_mission")
    mat_to_mat(f_path, cmp_dw, cmp_jk)

def convert_dw_pngs():
    global mat_list, not_found_list

    out_dir = str(dir_path / "png_conv") + "/DW_res/"
    for d in search_dirs:
        os.makedirs(out_dir + d, exist_ok=True)

    out_dir = str(dir_path / "mat_conv") + "/DW_res/"
    for d in search_dirs:
        os.makedirs(out_dir + d, exist_ok=True)


    cmp_dw = CmpPal(colormap_lut["dw_mission"])
    cmp_jk = CmpPal(colormap_lut["ui"])
    cmp_new = CmpPal(colormap_lut["ui"])
    for m in mat_list:
        convert_dw_png(m, cmp_dw, cmp_jk)
        #break

    dw_custom_start = 0x95
    jk_custom_start = 0xC0
    num_custom = 63
    push_newcolor = 254

    duplicates = []
    width = 16
    height = 16
    idx = 0
    img = []
    needs_fixups = []
    for y in range(height):
        row = ()
        for x in range(width):
            val = idx#data[(y*width) + x]
            color = (0xFF, 0x0, 0xFF)
            jk_matchidx = cmp_dw.find_matching_color(cmp_new, val)
            if jk_matchidx != -1 and jk_matchidx < jk_custom_start:
                color = cmp_dw.get_color(val)
            else:
                color = cmp_new.get_color(cmp_dw.closest_color(cmp_new, idx))

            if color not in duplicates:
                duplicates += [color]
                #color = (0xFF, 0x0, 0xFF)
            else:
                if val in not_found_list and val >= dw_custom_start and num_custom > 0:
                    color = cmp_dw.get_color(val)
                    needs_fixups += [(push_newcolor, val)]
                    num_custom -= 1
                    cmp_new.set_color(push_newcolor, color)
                    cmp_new.set_transparency(push_newcolor, cmp_dw.get_transparency(val))
                    push_newcolor -= 1
                #else:
                #    color = (0xFF, 0x0, 0xFF)
            #else:
            #    color = (0xFF, 0x0, 0xFF)

            #if val >= 0x95:
            #    color = (0xFF, 0x0, 0xFF)

            row = row + color
            idx += 1
        img.append(row)

    for i in needs_fixups:
        idx_new = i[0]
        idx_old = i[1]
        lightlevels = cmp_dw.get_lightlevels(idx_old)
        new_lightlevels = [0] * 0x40
        for j in range(0, 0x40):
            idx = lightlevels[j]
            new_lightlevels[j] = cmp_dw.closest_color(cmp_new, idx)

        cmp_new.set_lightlevels(idx_new, new_lightlevels)

    print(num_custom)

    with open(out_dir + "test.png", 'wb') as f_out:
        w = png.Writer(16, 16, greyscale=False)
        w.write(f_out, img)

    cmp_new.write_png(out_dir + "test2.png")
    cmp_new.write(out_dir + "test.cmp")

    for m in mat_list:
        close_lut = [-1] * 256
        for i in range(0, 256):
            close_lut[i] = cmp_dw.closest_color(cmp_new, i)
        mat_to_mat_2(m, cmp_dw, cmp_new, close_lut)

def convert_mat_to_correct_palette(desired_image_fpath, original_bm_fpath, output_fpath):
    desired_image = open(desired_image_fpath, "rb").read()
    original_bm = open(original_bm_fpath, "rb").read()

    desired_image_palraw = desired_image[-0x300:]
    original_bm_palraw = original_bm[-0x300:]
    cmp_desired = CmpPal(colormap_lut["ui"])
    cmp_original = CmpPal(colormap_lut["ui"])

    cmp_desired.pal_raw = desired_image_palraw
    cmp_original.pal_raw = original_bm_palraw

    print(cmp_desired.pal_raw)

    closest_lut = []
    for i in range(0, 256):
        closest_lut += [cmp_desired.closest_color(cmp_original, i, check_emissive=False)]
    closest_lut[0] = 0
    print(closest_lut)

    width = 256
    height = 192
    out_image_data = []
    desired_image_data = desired_image[0x88:]
    #original_image_data = desired_image[0x88:]
    for y in range(0, height):
        for x in range(0, width):
            val = desired_image_data[(y*width)+x]
            #color = cmp_original.closest_color(cmp_desired, val)
            color = closest_lut[val]
            out_image_data += [color]

    out_image_data = bytes(out_image_data)
    f = open(output_fpath, "wb")
    f.write(desired_image[:0x88])
    f.write(out_image_data)
    f.write(original_bm_palraw)
    f.close()

    cmp_desired.write_png("testA.png")
    cmp_original.write_png("testB.png")

#for i in range(0, num_textures):
#    print (textures[i])

#write_cmp_pngs()
#convert_dw_pngs()

# python3 scripts/assets/bm_to_bm.py "/Users/maxamillion/Library/Application Support/OpenJKDF2/openjkdf2/resource/ui/bm/new/bkmain.bm" "/Users/maxamillion/Library/Application Support/OpenJKDF2/openjkdf2/resource/ui/bm/originals/bkmain.bm" "/Users/maxamillion/Library/Application Support/OpenJKDF2/openjkdf2/resource/ui/bm/bkmain.bm"

if (len(sys.argv) < 3):
    print("Usage: mat_to_mat.py [valid_image_bad_palette.bm] [original_bm_with_good_palette.bm] [output.bm]")
print("adf")
convert_mat_to_correct_palette(sys.argv[1], sys.argv[2], sys.argv[3])
