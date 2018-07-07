#include "ddraw.h"

#include "uc_utils.h"
#include "main.h"

void DDraw::DirectDrawEnumerateA(uint32_t callback, uint32_t context)
{
    //printf("Jump to %x, ret %x\n", callback, callret_addr);

    //callret_ret = 0;
    //callret_ret_addr = ret_addr;

    // Map some memory for these strings
    // TODO: memleaks
    uint32_t ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    printf("got ptr %x\n", ptr);

    const char* driver_desc = "DirectDraw HAL";
    const char* driver_name = "display";
    uc_mem_write(current_uc, ptr, driver_desc, strlen(driver_desc));
    uc_mem_write(current_uc, ptr+strlen(driver_desc)+1, driver_name, strlen(driver_name));

    uint32_t callback_args[4] = {0, ptr, ptr+strlen(driver_desc)+1, context};
    uc_stack_push(current_uc, callback_args, 4);
    //uc_stack_push(current_uc, &callret_addr, 1); //TODO

    //pc_over = true;
    //uc_reg_write(current_uc, UC_X86_REG_EIP, &callback); //TODO this isn't working...
}

uint32_t DDraw::DirectDrawCreate(uint32_t a, uint32_t b, uint32_t c)
{
    return 1;
}

/*uint32_t DDraw::(uint32_t )
{
}*/
