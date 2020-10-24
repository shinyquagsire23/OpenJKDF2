funclist = open("ida_copypaste_funclist_nostdlib.txt", "r").read().split("\n")

file_sizes = {}
decomped_sizes = {}
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
    
    if funcname in decompiled_funcs:
        #print (funcname, filefrom)
        decomped_sizes[filefrom] += size
    
    total_size += size
    #print (filefrom, funcname, sect, start, size)

total_percent = 0
print ("[file]".ljust(30), "[size]".ljust(10), "[% of text]".ljust(13), "[% complete]".ljust(13))
for keyvalpair in sorted(file_sizes.items(), key=lambda item: item[1]):
    decomp_size = decomped_sizes[keyvalpair[0]]
    decomp_percent_num = (decomp_size/total_size)
    comp_percent_num = keyvalpair[1]/total_size
    total_percent += decomp_percent_num
    
    comp_percent = '{:.3%}'.format(comp_percent_num)
    decomp_percent = '{:.3%}'.format(decomp_percent_num/comp_percent_num)
    
    
    
    print (keyvalpair[0].ljust(30), hex(keyvalpair[1]).ljust(10), comp_percent.ljust(13), decomp_percent.ljust(13))

print("------------------------------\n")
print ("Total completion:", '{:.3%}'.format(total_percent))

