#include "ddraw.h"

#include "uc_utils.h"
#include "vm.h"
#include "winutils.h"
#include "dlls/kernel32.h"

uint32_t DDraw::DirectDrawEnumerateA(uint32_t callback, uint32_t context)
{
    // Map some memory for these strings
    // TODO: memleaks
    uint32_t ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    printf("got ptr %x\n", ptr);

    char* driver_desc = "DirectDraw HAL";
    char* driver_name = "display";
    vm_mem_write(ptr, driver_desc, strlen(driver_desc));
    vm_mem_write(ptr+strlen(driver_desc)+1, driver_name, strlen(driver_name));

    uint32_t callback_args[4] = {0xabcdef, ptr, ptr+strlen(driver_desc)+1, context};
    vm_call_function(callback, 4, callback_args);
    printf("back!\n");

    return 0;
}

uint32_t DDraw::DirectDrawCreate(uint8_t* lpGUID, uint32_t* lplpDD, void* pUnkOuter)
{
    printf("STUB! DirectDrawCreate");
    
    *lplpDD = CreateInterfaceInstance("IDirectDraw4", 200);
    
    return 1;
}

/*uint32_t DDraw::(uint32_t )
{
}*/
