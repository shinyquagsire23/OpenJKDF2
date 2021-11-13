funclist = open("ida_copypaste_funclist_nostdlib.txt", "r").read().split("\n")

funclist_noxref = open("noxrefs.txt").read().split("\n")

exclude_filefrom = ["nullsub", "menu", "init", "show", "gdi", "get", "cheat", "msgbox", "DialogFunc", "devcmd", "do", "idk", "wm", "WinIdk", "util", "cheats", "draw", "thing", "j", "sub", "daRealloc", "daFree", "daAlloc", "WinMain(x,x,x,x)", "WinCalibrateJoystick"]
filefrom_subsys = ["sith", "stdPlatform", "std", "jkGui", "rd", "jk", "Raster", "other"]

file_sizes = {}
decomped_sizes = {}
decomped_funcs = {}
total_funcs = {}
total_size = 0
total_numFuncs = 0
total_numFuncsNoRaster = 0
total_decompFuncs = 0
total_raster = 0

total_bySubsys = {}
total_decomp_bySubsys = {}
total_notdecomp_bySubsys = {}
total_decomp_funcs_bySubsys = {}
total_notdecomp_funcs_bySubsys = {}
total_funcs_bySubsys = {}

for subsys in filefrom_subsys:
    total_bySubsys[subsys] = 0
    total_funcs_bySubsys[subsys] = 0
    total_decomp_funcs_bySubsys[subsys] = 0
    total_notdecomp_funcs_bySubsys[subsys] = 0
    total_decomp_bySubsys[subsys] = 0
    total_notdecomp_bySubsys[subsys] = 0

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
    
    if funcname == "":
        continue

    filefrom = funcname.split("_")[0]
    
    if (len(funcname.split("_")) < 2 and filefrom[:2] == "rd"):
        filefrom = "rdroid"
    
    if (len(funcname.split("_")) < 2 and filefrom[:3] == "std"):
        filefrom = "stdPlatform"
    
    if "_" not in funcname and funcname.startswith("sith"):
        filefrom = "sith"

    is_excluded = False
    for exclude in exclude_filefrom:
        if (filefrom == exclude) or filefrom == "":
            is_excluded = True
            break

    '''if funcname in funclist_noxref:
        print (funcname)
        is_excluded = True'''

    if is_excluded:
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
    
    if funcname == "":
        continue
    
    filefrom = funcname.split("_")[0]
    
    if (len(funcname.split("_")) < 2 and filefrom[:2] == "rd"):
        filefrom = "rdroid"
    
    if (len(funcname.split("_")) < 2 and filefrom[:3] == "std"):
        filefrom = "stdPlatform"
    
    if "_" not in funcname and funcname.startswith("sith"):
        filefrom = "sith"
    
    is_excluded = False
    for exclude in exclude_filefrom:
        if (filefrom == exclude) or filefrom == "":
            is_excluded = True
            break

#    if funcname in funclist_noxref:
#        is_excluded = True

    if is_excluded:
        continue
    
#    if ("Raster" in filefrom):
#        continue
    
    if filefrom not in file_sizes:
        file_sizes[filefrom] = size
    else:
        file_sizes[filefrom] += size
    
    if filefrom not in decomped_sizes:
        decomped_sizes[filefrom] = 0
    
    if filefrom not in decomped_funcs:
        decomped_funcs[filefrom] = 0
        total_funcs[filefrom] = 0

    #if funcname not in decompiled_funcs:
    #    print (funcname, filefrom)
    
    found_func_subsys = False
    subsys_ident = "other"
    for subsys in filefrom_subsys:
        if filefrom.startswith(subsys):
            found_func_subsys = True

            if subsys == "rd" and "Raster" in filefrom:
                subsys = "Raster"
        
            subsys_ident = subsys
            break
    
    #if not found_func_subsys:
        #print (filefrom, subsys_ident)
    
    #if "cogMsg" in funcname and funcname not in decompiled_funcs:
    #    print (funcname)
    
    if funcname not in decompiled_funcs:
        total_notdecomp_bySubsys[subsys_ident] += size
        total_notdecomp_funcs_bySubsys[subsys_ident] += 1
    else:
        total_decomp_bySubsys[subsys_ident] += size
        total_decomp_funcs_bySubsys[subsys_ident] += 1
    total_bySubsys[subsys_ident] += size
    total_funcs_bySubsys[subsys_ident] += 1
    
    if funcname in decompiled_funcs:
        #print (funcname, filefrom)
        decomped_sizes[filefrom] += size
        decomped_funcs[filefrom] += 1
    
    total_funcs[filefrom] += 1
    total_size += size

    total_numFuncs += 1
    
    if subsys_ident == "Raster":
        total_raster += size
    else:
        total_numFuncsNoRaster += 1
    #print (filefrom, funcname, sect, start, size)

total_decomp = 0
print ("[file]".ljust(30), "[size]".ljust(10), "[% of text]".ljust(13), "[% complete]".ljust(13), "[decomp / total]".ljust(17))
# 100% functions
for keyvalpair in sorted(file_sizes.items(), key=lambda item: item[1]):
    decomp_size = decomped_sizes[keyvalpair[0]]
    decomp_percent_num = (decomp_size/total_size)
    comp_percent_num = keyvalpair[1]/total_size
    
    if (decomp_percent_num/comp_percent_num < 1.0):
        continue
    
    total_decomp += decomp_size
    
    comp_percent = '{:.3%}'.format(comp_percent_num)
    decomp_percent = '{:.3%}'.format(decomp_percent_num/comp_percent_num)
    decomp_fraction = str(decomped_funcs[keyvalpair[0]]).rjust(3) + " / " + str(total_funcs[keyvalpair[0]])
    
    total_decompFuncs += decomped_funcs[keyvalpair[0]]
    #total_numFuncs += total_funcs[keyvalpair[0]]
    
    print (keyvalpair[0].ljust(30), hex(keyvalpair[1]).ljust(10), comp_percent.ljust(13), decomp_percent.ljust(13), decomp_fraction.ljust(17))

# Not-100% functions
for keyvalpair in sorted(file_sizes.items(), key=lambda item: item[1]):
    decomp_size = decomped_sizes[keyvalpair[0]]
    decomp_percent_num = (decomp_size/total_size)
    comp_percent_num = keyvalpair[1]/total_size
    
    if (decomp_percent_num/comp_percent_num >= 1.0):
        continue
    
    total_decomp += decomp_size
    
    comp_percent = '{:.3%}'.format(comp_percent_num)
    decomp_percent = '{:.3%}'.format(decomp_percent_num/comp_percent_num)
    decomp_fraction = str(decomped_funcs[keyvalpair[0]]).rjust(3) + " / " + str(total_funcs[keyvalpair[0]])
    
    total_decompFuncs += decomped_funcs[keyvalpair[0]]
    #total_numFuncs += total_funcs[keyvalpair[0]]
    
    print (keyvalpair[0].ljust(30), hex(keyvalpair[1]).ljust(10), comp_percent.ljust(13), decomp_percent.ljust(13), decomp_fraction.ljust(17))

def percent_str(val, total):
    return '{:.3%}'.format(val/total)

def frac_str(val, val2):
    return str(val).rjust(4) + " / " + str(val2)

def decomp_totalPercent(val):
    return percent_str(val, total_size)

def decomp_totalPercent_noraster(val):
    return percent_str(val, total_size - total_raster)

print ("---------------------------------------------------------------------------------\n")
print ("Total completion:")
print ("-----------------")
print (decomp_totalPercent(total_decomp) + " by weight")
print (decomp_totalPercent_noraster(total_decomp) + " by weight excluding rasterizer")
print (str(total_decompFuncs) + " / " + str(total_numFuncs) + " functions")
print (str(total_decompFuncs) + " / " + str(total_numFuncsNoRaster) + " functions excluding rasterizer")

print ("")
print ("Subsystem Breakdown (Not Decomp'd)")
print ("----------------------------------")
totalAll = 0
totalFuncsAll = 0
numFuncsAll = 0
print ("[subsys]".ljust(15) + "[% of text]".ljust(13) + "[TODO / total]")
for subsys in filefrom_subsys:
    subsys_total = total_bySubsys[subsys]
    subsys_numFuncs = total_funcs_bySubsys[subsys]
    total = total_notdecomp_bySubsys[subsys]
    numFuncs = total_notdecomp_funcs_bySubsys[subsys]
    
    totalAll += total
    totalFuncsAll += numFuncs
    numFuncsAll += subsys_numFuncs
    
    print (subsys.ljust(15) + decomp_totalPercent(total).ljust(15) + frac_str(numFuncs, subsys_numFuncs))

print ("-----------------------------------------")
print ("total".ljust(15) + decomp_totalPercent(totalAll).ljust(15) + frac_str(totalFuncsAll, numFuncsAll))

print ("")
print ("Subsystem Breakdown (Not Decomp'd, Excl Raster)")
print ("-----------------------------------------------")
totalAll = 0
totalFuncsAll = 0
numFuncsAll = 0
print ("[subsys]".ljust(15) + "[% of text]".ljust(13) + "[TODO / total]")
for subsys in filefrom_subsys:
    if subsys == "Raster":
        continue
    subsys_total = total_bySubsys[subsys]
    subsys_numFuncs = total_funcs_bySubsys[subsys]
    total = total_notdecomp_bySubsys[subsys]
    numFuncs = total_notdecomp_funcs_bySubsys[subsys]
    
    totalAll += total
    totalFuncsAll += numFuncs
    numFuncsAll += subsys_numFuncs
    
    print (subsys.ljust(15) + decomp_totalPercent_noraster(total).ljust(15) + frac_str(numFuncs, subsys_numFuncs))

print ("-----------------------------------------")
print ("total".ljust(15) + decomp_totalPercent_noraster(totalAll).ljust(15) + frac_str(totalFuncsAll, numFuncsAll))

print ("")
