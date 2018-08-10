#include "winutils.h"

#include <QMetaMethod>

#include "dlls/kernel32.h"
#include "vm.h"
#include "main.h"

std::string guid_to_string(uint8_t* lpGUID)
{
    char tmp[256];
    sprintf(tmp, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", *(uint32_t*)&lpGUID[0], *(uint16_t*)&lpGUID[4], *(uint16_t*)&lpGUID[6], lpGUID[8], lpGUID[9], lpGUID[10], lpGUID[11], lpGUID[12], lpGUID[13], lpGUID[14], lpGUID[15]);
    
    return std::string(tmp);
}

uint32_t CreateInterfaceInstance(std::string name, int num_funcs)
{
    vm_ptr<uint32_t*> imem = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
    vm_ptr<uint32_t*> vtable = {kernel32->VirtualAlloc(0, (num_funcs*sizeof(uint32_t))&~0xFFF + 0x1000, 0, 0)};
    
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
    
    *imem.translated() = vtable.raw_vm_ptr;
    return imem.raw_vm_ptr;
}
