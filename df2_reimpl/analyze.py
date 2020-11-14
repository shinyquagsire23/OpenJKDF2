funclist = open("ida_copypaste_funclist_nostdlib.txt", "r").read().split("\n")

exclude_filefrom = ["nullsub", "sithCorpse", "menu", "init", "show", "gdi", "get", "cheat", "msgbox", "DialogFunc", "devcmd", "do", "idk", "wm", "WinIdk", "util", "cheats", "draw", "thing", "j", "sub", "daRealloc", "daFree", "daAlloc", "WinMain(x,x,x,x)", "WinCalibrateJoystick", ""]
file_sizes = {}
decomped_sizes = {}
decomped_funcs = {}
total_funcs = {}
total_size = 0

mapread = open("output.map", "r").read().split("\n")

decompiled_funcs = []
foundFuncs = False
for line in mapread:
    if ("SIZEOF_HEADERS" not in line and not foundFuncs):
        continue
    if (not foundFuncs and "SIZEOF_HEADERS" in line):
        foundFuncs = True
    if (".data" in line):
        break
    if (".text" in line):
        continue

    split = line.split(" ")
    funcname = split[len(split)-1]
    if ("(" in funcname or "*" in funcname or "0x" in funcname or "." in funcname):
        continue
    
    decompiled_funcs += [funcname]

decompiled_funcs = list(decompiled_funcs)

for line in funclist:
    split = line.split("\t")
    if (len(split) < 3):
        continue
    funcname = split[0]
    sect = split[1]
    start = int(split[2], 16)
    size = int(split[3], 16)
    
    filefrom = funcname.split("_")[0]
    
    if (len(funcname.split("_")) < 2 and filefrom[:2] == "rd"):
        filefrom = "rdroid"
    
    if (len(funcname.split("_")) < 2 and filefrom[:3] == "std"):
        filefrom = "stdPlatform"
    
    if (filefrom == "j" or filefrom == "sub"):
        continue
    
    if filefrom not in file_sizes:
        file_sizes[filefrom] = size
    else:
        file_sizes[filefrom] += size
    
    if filefrom not in decomped_sizes:
        decomped_sizes[filefrom] = 0
    
    if filefrom not in decomped_funcs:
        decomped_funcs[filefrom] = 0
        total_funcs[filefrom] = 0
    
    #if funcname not in decompiled_funcs and filefrom == "sithModel":
    #    print (funcname, filefrom)
    
    if funcname in decompiled_funcs:
        #print (funcname, filefrom)
        decomped_sizes[filefrom] += size
        decomped_funcs[filefrom] += 1
    
    total_funcs[filefrom] += 1
    total_size += size
    #print (filefrom, funcname, sect, start, size)

total_decomp = 0
print ("[file]".ljust(30), "[size]".ljust(10), "[% of text]".ljust(13), "[% complete]".ljust(13), "[decomp / total]".ljust(17))
for keyvalpair in sorted(file_sizes.items(), key=lambda item: item[1]):
    if (keyvalpair[0] in exclude_filefrom):
        continue

    decomp_size = decomped_sizes[keyvalpair[0]]
    decomp_percent_num = (decomp_size/total_size)
    comp_percent_num = keyvalpair[1]/total_size
    
    if (decomp_percent_num/comp_percent_num < 1.0):
        continue
    
    total_decomp += decomp_size
    
    comp_percent = '{:.3%}'.format(comp_percent_num)
    decomp_percent = '{:.3%}'.format(decomp_percent_num/comp_percent_num)
    decomp_fraction = str(decomped_funcs[keyvalpair[0]]).rjust(3) + " / " + str(total_funcs[keyvalpair[0]])
    
    
    print (keyvalpair[0].ljust(30), hex(keyvalpair[1]).ljust(10), comp_percent.ljust(13), decomp_percent.ljust(13), decomp_fraction.ljust(17))

for keyvalpair in sorted(file_sizes.items(), key=lambda item: item[1]):
    if (keyvalpair[0] in exclude_filefrom):
        continue

    decomp_size = decomped_sizes[keyvalpair[0]]
    decomp_percent_num = (decomp_size/total_size)
    comp_percent_num = keyvalpair[1]/total_size
    
    if (decomp_percent_num/comp_percent_num >= 1.0):
        continue
    
    total_decomp += decomp_size
    
    comp_percent = '{:.3%}'.format(comp_percent_num)
    decomp_percent = '{:.3%}'.format(decomp_percent_num/comp_percent_num)
    decomp_fraction = str(decomped_funcs[keyvalpair[0]]).rjust(3) + " / " + str(total_funcs[keyvalpair[0]])
    
    
    print (keyvalpair[0].ljust(30), hex(keyvalpair[1]).ljust(10), comp_percent.ljust(13), decomp_percent.ljust(13), decomp_fraction.ljust(17))

print("------------------------------\n")
print ("Total completion:", '{:.3%}'.format(total_decomp/total_size))

