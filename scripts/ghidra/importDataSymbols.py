# Import symbols.syms into Ghidra
#
# @category OpenJKDF2.Data
#

from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import IntegerDataType, StructureDataType, UnsignedLongLongDataType, \
    PointerDataType,FunctionDefinitionDataType,TypedefDataType,VoidDataType,ArrayDataType
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Select symbols.syms", "Select symbols.syms")
for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
    if len(line) < 2: continue

    if line[:2] == "//": continue
    if line[:1] == "#": continue

    line = line.split("//")[0]
    pieces = line.split(" ")
    if (len(pieces) < 3): continue

    name = pieces[0]
    addr_int = long(pieces[1], 16)
    address = toAddr(addr_int)
    sym_type_and_val = " ".join(pieces[2:])
    sym_type = sym_type_and_val.split(" = ")[0].replace("\n", "").replace(" ", "")
    sym_val = sym_type_and_val.split(" = ")[-1].replace("\n", "").replace(" ", "")

    if sym_type == sym_val:
        sym_val = ""

    print("Created label {} at address {}, type {} val {}".format(name, address, sym_type, sym_val))
    createLabel(address, name, True)

    if "*" not in sym_type and "[" not in sym_type:
        base_type = sym_type
        the_rest = ""
    else:
        base_type = sym_type.split("*")[0].split("[")[0]
        the_rest = sym_type.split(base_type)[-1]

    dtm = currentProgram.getDataTypeManager()
    #n = currentProgram.getName()+ "/"+sym_type
    #print (n)
    #dt = dtm.findDataType(n)
    l = getDataTypes(base_type)
    if len(l) > 0:
        dt = l[0]
    else:
        dt = getDataTypes("undefined4")[0]

    defines = {
        "RDCACHE_MAX_TRIS":0x400,
        "RDCACHE_MAX_VERTICES":0x8000,
        "SITH_MAX_SYNC_THINGS":16,
        "JK_NUM_JOYSTICKS":2,
        "JK_NUM_MOUSE_AXES":3,
        "JK_NUM_AXES":15,
        "JK_NUM_KEYS":284,
        "256+1":257,
        "SITHBIN_NUMBINS":200,
    }

    idx = 0
    while True:
        if idx >= len(the_rest):
            break
        if the_rest[idx] == '*':
            dt = PointerDataType(dt)
        elif the_rest[idx] == '[':
            amt_str = the_rest[idx+1:].split("]")[0]
            if amt_str in defines:
                amt = defines[amt_str]
            elif len(amt_str) >= 3 and amt_str[:2] == "0x":
                amt = int(amt_str, 16)
            else:
                amt = int(amt_str)
            dt = ArrayDataType(dt, amt, dt.getLength())
            idx += len(amt_str) + 1
        idx += 1

    print(base_type, the_rest, dt)
    dt_len = 0
    if dt is not None:
        dt_len = dt.getLength()

    
    if dt is not None:
        for i in range(0, dt_len):
            removeDataAt(toAddr(addr_int+i))
        createData(address, dt)


