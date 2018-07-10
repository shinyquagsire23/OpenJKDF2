#include "ddraw.h"

#include "uc_utils.h"
#include "main.h"
#include "winutils.h"

uint32_t DDraw::DirectDrawEnumerateA(uint32_t callback, uint32_t context)
{
    // Map some memory for these strings
    // TODO: memleaks
    uint32_t ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    printf("got ptr %x\n", ptr);

    const char* driver_desc = "DirectDraw HAL";
    const char* driver_name = "display";
    uc_mem_write(current_uc, ptr, driver_desc, strlen(driver_desc));
    uc_mem_write(current_uc, ptr+strlen(driver_desc)+1, driver_name, strlen(driver_name));

    uint32_t callback_args[4] = {0xabcdef, ptr, ptr+strlen(driver_desc)+1, context};
    call_function(callback, 4, callback_args);
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
