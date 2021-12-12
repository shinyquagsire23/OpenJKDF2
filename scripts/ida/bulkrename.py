import idautils
import idaapi

rename_prefix_from = "sithCogPlayer_"
rename_prefix_to = "sithCogFunctionPlayer_"

for f in idautils.Functions():
    name = ida_funcs.get_func_name(f)
    if name.startswith(rename_prefix_from):
            newname = name.replace(rename_prefix_from, rename_prefix_to)
            idaapi.set_name(f, newname, idaapi.SN_FORCE)