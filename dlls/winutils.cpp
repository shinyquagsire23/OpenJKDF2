#include "winutils.h"

#include <QMetaMethod>

#include "dlls/kernel32.h"
#include "vm.h"
#include "main.h"

std::map<std::string, uint32_t> vtable_store;

std::string guid_to_string(uint8_t* lpGUID)
{
    if (!lpGUID)
        return "(null GUID)";

    char tmp[256];
    sprintf(tmp, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", *(uint32_t*)&lpGUID[0], *(uint16_t*)&lpGUID[4], *(uint16_t*)&lpGUID[6], lpGUID[8], lpGUID[9], lpGUID[10], lpGUID[11], lpGUID[12], lpGUID[13], lpGUID[14], lpGUID[15]);
    
    return std::string(tmp);
}

uint32_t CreateInterfaceInstance(std::string name, int num_funcs)
{
    vm_ptr<uint32_t*> imem = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
    vm_ptr<uint32_t*> vtable = {kernel32->VirtualAlloc(0, (num_funcs*sizeof(uint32_t))&~0xFFF + 0x1000, 0, 0)};
    
    memset(imem.translated(), 0, 0x1000);
    
    for (int i = 0; i < num_funcs; i++)
    {
        if (interface_store[name])
        {
            QMetaMethod method = interface_store[name]->metaObject()->method(i + 5); //TODO: idk about this hardcoded shift
            std::string method_name = std::string((char*)method.name().data());
            
            if (method_name == "") break;
            
            register_import(name, std::string(method_name), 0);
            
            vtable.translated()[i] = import_get_hook_addr(name, std::string(method_name));
            //printf("finding %u, %s, %x\n", i, method_name.c_str(), import_get_hook_addr(name, std::string(method_name)));
        }
        else
        {
            char tmp[256];
            
            snprintf(tmp, 256, "%s_%u", name.c_str(), i);
            register_import(name, std::string(tmp), 0);
            
            vtable.translated()[i] = import_get_hook_addr(name, std::string(tmp));
        }
    }
    
    vm_sync_imports();

    printf("%s vtable %x, obj %x\n", name.c_str(), vtable.raw_vm_ptr, imem.raw_vm_ptr);

    *imem.translated() = vtable.raw_vm_ptr;
    return imem.raw_vm_ptr;
}

uint32_t GlobalQueryInterface(std::string iid_str, uint32_t* lpInterface)
{
    if (iid_str == "3bba0080-2421-11cf-a31a-00aa00b93356")
    {
        *lpInterface = CreateInterfaceInstance("IDirect3D3", 64);
        return 0;
    }
    else if (iid_str == "0194c220-a303-11d0-9c4f-00a0c905425e")
    {
        *lpInterface = CreateInterfaceInstance("IDirectPlayLobby3", 16);
        return 0;
    }
    else if (iid_str == "b3a6f3e0-2b43-11cf-a2de-00aa00b93356")
    {
        *lpInterface = CreateInterfaceInstance("IDirectDraw4", 32);
        return 0;
    }
    else if (iid_str == "62626262-6262-6262-6262-626262626262" 
             || iid_str == "87051a80-13fc-11d1-97c0-00a024293005")
    {
        *lpInterface = CreateInterfaceInstance("IDirect3DDevice", 64);
        return 0;
    }
    else if (iid_str == "2cdcd9e0-25a0-11cf-a31a-00aa00b93356")
    {
        *lpInterface = CreateInterfaceInstance("IDirect3DTexture", 64);
        return 0;
    }

    return 1;
}

void GlobalRelease(void* this_ptr)
{
    kernel32->VirtualFree(*(uint32_t*)this_ptr, 0, 0);
    kernel32->VirtualFree(real_ptr_to_vm_ptr(this_ptr), 0, 0); //TODO
}
