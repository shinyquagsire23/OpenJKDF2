#include "winutils.h"

#include <QMetaMethod>

#include "main.h"
#include "uc_utils.h"

std::string guid_to_string(uint8_t* lpGUID)
{
    char tmp[256];
    sprintf(tmp, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", *(uint32_t*)&lpGUID[0], *(uint16_t*)&lpGUID[4], *(uint16_t*)&lpGUID[6], lpGUID[8], lpGUID[9], lpGUID[10], lpGUID[11], lpGUID[12], lpGUID[13], lpGUID[14], lpGUID[15]);
    
    return std::string(tmp);
}

uint32_t CreateInterfaceInstance(std::string name, int num_funcs)
{
    uint32_t* imem = (uint32_t*)uc_ptr_to_real_ptr(kernel32->VirtualAlloc(0, 0x1000, 0, 0));
    uint32_t* vtable = (uint32_t*)uc_ptr_to_real_ptr(kernel32->VirtualAlloc(0, (num_funcs*sizeof(uint32_t))&~0xFFF + 0x1000, 0, 0));
    
    kernel32->Unicorn_MapHeaps();
    
    for (int i = 0; i < num_funcs; i++)
    {
        if (interface_store[name])
        {
            QMetaMethod method = interface_store[name]->metaObject()->method(i + 5); //TODO: idk about this hardcoded shift
            std::string method_name = std::string((char*)method.name().data());
            
            //printf("finding %u, %s\n", i, method_name.c_str());
            
            register_import(name, std::string(method_name), 0);
            
            vtable[i] = import_get_hook_addr(std::string(method_name));
        }
        else
        {
            char tmp[256];
            
            snprintf(tmp, 256, "%s_%u", name.c_str(), i);
            register_import(name, std::string(tmp), 0);
            
            vtable[i] = import_get_hook_addr(std::string(tmp));
        }
    }
    
    vm_sync_imports();
    
    *imem = real_ptr_to_uc_ptr(vtable);
    return real_ptr_to_uc_ptr(imem);
}
