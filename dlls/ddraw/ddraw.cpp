#include "ddraw.h"

#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/kernel32.h"

uint32_t DDraw::DirectDrawEnumerateA(uint32_t callback, uint32_t context)
{
    // Map some memory for these strings
    // TODO: memleaks
    uint32_t ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    printf("got ptr %x\n", ptr);

    char* driver_desc = "DirectDraw HAL";
    char* driver_name = "display";
    char* guid = "aaaaaaaaaaaaaaaa";
    
    uint32_t driver_desc_ptr = ptr;
    uint32_t driver_name_ptr = ptr+strlen(driver_desc)+1;
    uint32_t guid_ptr = driver_name_ptr+strlen(driver_name)+1;
    
    vm_mem_write(driver_desc_ptr, driver_desc, strlen(driver_desc));
    vm_mem_write(driver_name_ptr, driver_name, strlen(driver_name));
    vm_mem_write(guid_ptr, guid, strlen(guid));

    vm_call_func(callback, guid_ptr, driver_name_ptr, driver_desc_ptr, context);
    printf("back!\n");

    return 0;
}

uint32_t DDraw::DirectDrawCreate(uint8_t* lpGUID, uint32_t* lplpDD, void* pUnkOuter)
{
    printf("STUB! DirectDrawCreate %s\n", guid_to_string(lpGUID).c_str());
    
    *lplpDD = CreateInterfaceInstance("IDirectDraw4", 200);
    
    return this->force_error; // TODO: 0 for 3D stuff
}

/*uint32_t DDraw::(uint32_t )
{
}*/
